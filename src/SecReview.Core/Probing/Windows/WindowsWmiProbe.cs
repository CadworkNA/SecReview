using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.System.Com;
using Windows.Win32.System.Variant;
using Windows.Win32.System.Wmi;

namespace SecReview.Probing.Windows;

/// <summary>
/// Runs read-only WMI queries through the WMI COM interfaces (the same service PowerShell's
/// Get-CimInstance talks to), without starting PowerShell.
/// </summary>
[SupportedOSPlatform(MinimumWindows.Platform)]
internal sealed class WindowsWmiProbe : IWmiProbe
{
    private const string What = "Querying Windows Management Instrumentation";

    /// <summary>How long to wait for each object; WMI providers can hang.</summary>
    private const int NextTimeoutMilliseconds = 15_000;

    /// <summary>More objects than this means the query was not what we meant to ask.</summary>
    private const int MaximumObjects = 2_000;

    private const uint AuthenticationWinNt = 10;    // RPC_C_AUTHN_WINNT
    private const uint AuthorizationNone = 0;       // RPC_C_AUTHZ_NONE

    private const int WbemNoMoreData = 1;                                  // WBEM_S_FALSE
    private const int WbemTimedOut = 0x00040004;                           // WBEM_S_TIMEDOUT
    private const int WbemAccessDenied = unchecked((int)0x80041003);
    private const int WbemNotFound = unchecked((int)0x80041002);
    private const int WbemInvalidNamespace = unchecked((int)0x8004100E);
    private const int WbemInvalidClass = unchecked((int)0x80041010);

    public unsafe ProbeResult<IReadOnlyList<WmiObject>> Query(
        string wmiNamespace, string className, IReadOnlyList<string> properties)
    {
        ArgumentNullException.ThrowIfNull(properties);
        if (!IsNamespace(wmiNamespace) || !IsIdentifier(className) || properties.Count == 0 ||
            !properties.All(IsIdentifier))
        {
            // Names are put into the query text, so anything but plain identifiers is refused.
            return ProbeFailure.Failed($"{What} failed: invalid namespace, class or property name.");
        }

        using ComScope com = ComScope.Enter();

        IWbemLocator* locator = null;
        IWbemServices* services = null;
        IEnumWbemClassObject* enumerator = null;
        BSTR namespaceText = default;
        BSTR language = default;
        BSTR query = default;
        try
        {
            HRESULT created = WbemLocator.CreateInstance(out locator);
            if (created.Failed)
            {
                return WindowsError.FromHResult(created.Value, What);
            }

            namespaceText = PInvoke.SysAllocString(wmiNamespace);
            language = PInvoke.SysAllocString("WQL");
            query = PInvoke.SysAllocString($"SELECT {string.Join(",", properties)} FROM {className}");

            locator->ConnectServer(namespaceText, default, default, default, 0, default, null, &services);

            // Let the WMI service act as the caller, so it applies the caller's own rights.
            HRESULT secured = PInvoke.CoSetProxyBlanket(
                (IUnknown*)services,
                AuthenticationWinNt,
                AuthorizationNone,
                null,
                RPC_C_AUTHN_LEVEL.RPC_C_AUTHN_LEVEL_CALL,
                RPC_C_IMP_LEVEL.RPC_C_IMP_LEVEL_IMPERSONATE,
                null,
                EOLE_AUTHENTICATION_CAPABILITIES.EOAC_NONE);
            if (secured.Failed)
            {
                return FromWmi(secured.Value, className);
            }

            services->ExecQuery(
                language,
                query,
                WBEM_GENERIC_FLAG_TYPE.WBEM_FLAG_FORWARD_ONLY | WBEM_GENERIC_FLAG_TYPE.WBEM_FLAG_RETURN_IMMEDIATELY,
                null,
                &enumerator);

            var objects = new List<WmiObject>();
            while (true)
            {
                IWbemClassObject* instance = null;
                HRESULT next = enumerator->Next(NextTimeoutMilliseconds, 1, &instance, out uint returned);
                if (next.Failed)
                {
                    return FromWmi(next.Value, className);
                }

                if (next.Value == WbemTimedOut)
                {
                    return ProbeFailure.Failed($"{What} failed: {className} did not answer in time.");
                }

                if (returned == 0 || next.Value == WbemNoMoreData && instance is null)
                {
                    break;
                }

                try
                {
                    objects.Add(Read(instance, properties));
                }
                finally
                {
                    instance->Release();
                }

                if (objects.Count > MaximumObjects)
                {
                    return ProbeFailure.Failed($"{What} failed: {className} returned too many objects.");
                }
            }

            return ProbeResult<IReadOnlyList<WmiObject>>.Ok(objects);
        }
        catch (COMException exception)
        {
            return FromWmi(exception.HResult, className);
        }
        catch (Exception exception)
        {
            return WindowsError.FromException(exception, What);
        }
        finally
        {
            if (enumerator is not null)
            {
                enumerator->Release();
            }

            if (services is not null)
            {
                services->Release();
            }

            if (locator is not null)
            {
                locator->Release();
            }

            PInvoke.SysFreeString(query);
            PInvoke.SysFreeString(language);
            PInvoke.SysFreeString(namespaceText);
        }
    }

    private static ProbeFailure FromWmi(int hresult, string className) => hresult switch
    {
        WbemAccessDenied => ProbeFailure.AccessDenied(),
        WbemInvalidNamespace or WbemInvalidClass or WbemNotFound =>
            ProbeFailure.NotSupported($"This edition of Windows does not provide {className}."),
        _ => WindowsError.FromHResult(hresult, What),
    };

    private static unsafe WmiObject Read(IWbemClassObject* instance, IReadOnlyList<string> properties)
    {
        var values = new List<KeyValuePair<string, object?>>(properties.Count);
        foreach (string property in properties)
        {
            VARIANT value = default;
            try
            {
                instance->Get(property, 0, ref value);
                values.Add(new KeyValuePair<string, object?>(property, Convert(value)));
            }
            finally
            {
                _ = PInvoke.VariantClear(ref value);
            }
        }

        return new WmiObject(values);
    }

    /// <summary>Copies a value out of a VARIANT; types SecReview has no use for become null.</summary>
    private static unsafe object? Convert(in VARIANT value)
    {
        VARENUM type = value.Anonymous.Anonymous.vt;
        ref readonly var data = ref value.Anonymous.Anonymous.Anonymous;

        if ((type & VARENUM.VT_ARRAY) != 0)
        {
            return ConvertArray(data.parray, type & ~VARENUM.VT_ARRAY);
        }

        return type switch
        {
            VARENUM.VT_BSTR => data.bstrVal.ToString(),
            VARENUM.VT_BOOL => data.boolVal != VARIANT_BOOL.VARIANT_FALSE,
            VARENUM.VT_I4 or VARENUM.VT_INT => (long)data.lVal,
            VARENUM.VT_UI4 or VARENUM.VT_UINT => (long)data.ulVal,
            VARENUM.VT_I2 => (long)data.iVal,
            VARENUM.VT_UI1 => (long)data.bVal,
            VARENUM.VT_I8 => data.llVal,
            _ => null,
        };
    }

    private static unsafe object? ConvertArray(SAFEARRAY* array, VARENUM elementType)
    {
        if (array is null ||
            PInvoke.SafeArrayGetLBound(array, 1, out int lower).Failed ||
            PInvoke.SafeArrayGetUBound(array, 1, out int upper).Failed)
        {
            return null;
        }

        switch (elementType)
        {
            case VARENUM.VT_BSTR:
                var texts = new List<string>();
                for (int index = lower; index <= upper; index++)
                {
                    BSTR element = default;
                    if (PInvoke.SafeArrayGetElement(array, in index, &element).Succeeded)
                    {
                        // SafeArrayGetElement hands back a copy that the caller frees.
                        texts.Add(Bstr.Take(element));
                    }
                }

                return (IReadOnlyList<string>)texts;

            case VARENUM.VT_I4 or VARENUM.VT_INT or VARENUM.VT_UI4 or VARENUM.VT_UINT:
                var numbers = new List<long>();
                for (int index = lower; index <= upper; index++)
                {
                    int element = 0;
                    if (PInvoke.SafeArrayGetElement(array, in index, &element).Succeeded)
                    {
                        numbers.Add(elementType is VARENUM.VT_UI4 or VARENUM.VT_UINT ? (uint)element : element);
                    }
                }

                return (IReadOnlyList<long>)numbers;

            case VARENUM.VT_UI1:
                var bytes = new List<long>();
                for (int index = lower; index <= upper; index++)
                {
                    byte element = 0;
                    if (PInvoke.SafeArrayGetElement(array, in index, &element).Succeeded)
                    {
                        bytes.Add(element);
                    }
                }

                return (IReadOnlyList<long>)bytes;

            default:
                return null;
        }
    }

    private static bool IsIdentifier(string? text) =>
        !string.IsNullOrEmpty(text) && text.All(c => char.IsAsciiLetterOrDigit(c) || c == '_');

    private static bool IsNamespace(string? text) =>
        !string.IsNullOrEmpty(text) && text.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '\\');
}
