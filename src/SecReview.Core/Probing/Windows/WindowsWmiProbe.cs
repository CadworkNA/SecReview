using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.System.Com;
using Windows.Win32.System.Variant;
using Windows.Win32.System.Wmi;

namespace SecReview.Probing.Windows;

/// <summary>
/// Runs read-only WMI queries on this PC through the WMI COM interfaces (the same service
/// PowerShell's Get-CimInstance talks to), without starting PowerShell.
/// </summary>
[SupportedOSPlatform(MinimumWindows.Platform)]
internal sealed class WindowsWmiProbe : IWmiProbe
{
    private const string What = "Querying Windows Management Instrumentation";

    /// <summary>How long to wait for each object; WMI providers can hang.</summary>
    private const int NextTimeoutMilliseconds = 15_000;

    /// <summary>How long one query may take in total, however slowly objects arrive.</summary>
    private static readonly TimeSpan TotalBudget = TimeSpan.FromSeconds(45);

    /// <summary>More objects than this means the query was not what we meant to ask.</summary>
    private const int MaximumObjects = 2_000;

    /// <summary>Makes ConnectServer give up after about two minutes instead of waiting forever.</summary>
    private const int ConnectUseMaxWait = 0x80;     // WBEM_FLAG_CONNECT_USE_MAX_WAIT

    private const uint AuthenticationWinNt = 10;    // RPC_C_AUTHN_WINNT
    private const uint AuthorizationNone = 0;       // RPC_C_AUTHZ_NONE

    private const int WbemNoMoreData = 1;                                  // WBEM_S_FALSE
    private const int WbemTimedOut = 0x00040004;                           // WBEM_S_TIMEDOUT
    private const int WbemAccessDenied = unchecked((int)0x80041003);
    private const int WbemNotFound = unchecked((int)0x80041002);
    private const int WbemInvalidNamespace = unchecked((int)0x8004100E);
    private const int WbemInvalidClass = unchecked((int)0x80041010);

    // CIM types that decide how a VARIANT is read: WMI hands unsigned integers over in signed
    // VARIANT types, so the declared type says whether a value above 2^31 is really negative.
    private const int CimUInt16 = 18;
    private const int CimUInt32 = 19;
    private const int CimArrayFlag = 0x2000;

    public unsafe ProbeResult<IReadOnlyList<WmiObject>> Query(
        string wmiNamespace, string className, IReadOnlyList<string> properties, WmiFlagFilter? only = null)
    {
        ArgumentNullException.ThrowIfNull(properties);
        if (!WmiNames.IsLocalNamespace(wmiNamespace) || !WmiNames.IsIdentifier(className) ||
            properties.Count == 0 || !properties.All(WmiNames.IsIdentifier) ||
            (only is not null && !WmiNames.IsIdentifier(only.Property)))
        {
            // Names are put into the query text, and a namespace could otherwise name another
            // computer, so anything but a local namespace and plain identifiers is refused.
            return ProbeFailure.Failed($"{What} failed: invalid namespace, class or property name.");
        }

        using ComScope com = ComScope.Enter();
        var elapsed = Stopwatch.StartNew();

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
            string condition = only is null ? string.Empty : $" WHERE {only.Property} = {(only.Value ? "TRUE" : "FALSE")}";
            query = PInvoke.SysAllocString($"SELECT {string.Join(",", properties)} FROM {className}{condition}");

            locator->ConnectServer(
                namespaceText, default, default, default, ConnectUseMaxWait, default, null, &services);

            // Let the WMI service act as the caller, so it applies the caller's own rights.
            HRESULT secured = PInvoke.CoSetProxyBlanket(
                (IUnknown*)services,
                AuthenticationWinNt,
                AuthorizationNone,
                null,
                RPC_C_AUTHN_LEVEL.RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
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
                if (elapsed.Elapsed > TotalBudget)
                {
                    return ProbeFailure.Failed($"{What} failed: {className} took too long to answer.");
                }

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

                if (returned == 0 || (next.Value == WbemNoMoreData && instance is null))
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
        catch (InvalidDataException exception)
        {
            // A value could not be read completely. Report that, rather than hand back data
            // with something silently missing.
            return ProbeFailure.Failed($"{What} failed: {exception.Message}");
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
                instance->Get(property, 0, ref value, out int cimType, out _);
                values.Add(new KeyValuePair<string, object?>(property, Convert(value, cimType, property)));
            }
            finally
            {
                _ = PInvoke.VariantClear(ref value);
            }
        }

        return new WmiObject(values);
    }

    /// <summary>
    /// Copies a value out of a VARIANT. A type this code does not read is an error, not an
    /// empty value: "nothing there" and "could not read" must stay different.
    /// </summary>
    private static unsafe object? Convert(in VARIANT value, int cimType, string property)
    {
        VARENUM type = value.Anonymous.Anonymous.vt;
        ref readonly var data = ref value.Anonymous.Anonymous.Anonymous;
        int baseCimType = cimType & ~CimArrayFlag;

        if ((type & VARENUM.VT_ARRAY) != 0)
        {
            return ConvertArray(data.parray, type & ~VARENUM.VT_ARRAY, baseCimType, property);
        }

        return type switch
        {
            VARENUM.VT_NULL or VARENUM.VT_EMPTY => null,
            VARENUM.VT_BSTR => data.bstrVal.ToString(),
            VARENUM.VT_BOOL => data.boolVal != VARIANT_BOOL.VARIANT_FALSE,
            VARENUM.VT_I4 or VARENUM.VT_INT => baseCimType == CimUInt32 ? (uint)data.lVal : (long)data.lVal,
            VARENUM.VT_UI4 or VARENUM.VT_UINT => (long)data.ulVal,
            VARENUM.VT_I2 => baseCimType == CimUInt16 ? (ushort)data.iVal : (long)data.iVal,
            VARENUM.VT_UI1 => (long)data.bVal,
            VARENUM.VT_I8 => data.llVal,
            VARENUM.VT_R4 => (double)data.fltVal,
            VARENUM.VT_R8 => data.dblVal,
            _ => throw Unreadable(property, (int)type),
        };
    }

    private static unsafe object ConvertArray(SAFEARRAY* array, VARENUM elementType, int baseCimType, string property)
    {
        if (array is null ||
            PInvoke.SafeArrayGetLBound(array, 1, out int lower).Failed ||
            PInvoke.SafeArrayGetUBound(array, 1, out int upper).Failed)
        {
            throw Unreadable(property, (int)(elementType | VARENUM.VT_ARRAY));
        }

        switch (elementType)
        {
            case VARENUM.VT_BSTR:
                var texts = new List<string>();
                for (int index = lower; index <= upper; index++)
                {
                    BSTR element = default;
                    Require(PInvoke.SafeArrayGetElement(array, in index, &element), property);

                    // SafeArrayGetElement hands back a copy that the caller frees.
                    texts.Add(Bstr.Take(element));
                }

                return (IReadOnlyList<string>)texts;

            case VARENUM.VT_I4 or VARENUM.VT_INT or VARENUM.VT_UI4 or VARENUM.VT_UINT:
                bool unsigned = baseCimType == CimUInt32 || elementType is VARENUM.VT_UI4 or VARENUM.VT_UINT;
                var numbers = new List<long>();
                for (int index = lower; index <= upper; index++)
                {
                    int element = 0;
                    Require(PInvoke.SafeArrayGetElement(array, in index, &element), property);
                    numbers.Add(unsigned ? (uint)element : element);
                }

                return (IReadOnlyList<long>)numbers;

            case VARENUM.VT_I2:
                var shorts = new List<long>();
                for (int index = lower; index <= upper; index++)
                {
                    short element = 0;
                    Require(PInvoke.SafeArrayGetElement(array, in index, &element), property);
                    shorts.Add(baseCimType == CimUInt16 ? (ushort)element : element);
                }

                return (IReadOnlyList<long>)shorts;

            case VARENUM.VT_UI1:
                var bytes = new List<long>();
                for (int index = lower; index <= upper; index++)
                {
                    byte element = 0;
                    Require(PInvoke.SafeArrayGetElement(array, in index, &element), property);
                    bytes.Add(element);
                }

                return (IReadOnlyList<long>)bytes;

            default:
                throw Unreadable(property, (int)(elementType | VARENUM.VT_ARRAY));
        }
    }

    private static void Require(HRESULT result, string property)
    {
        if (result.Failed)
        {
            throw new InvalidDataException($"an element of {property} could not be read.");
        }
    }

    private static InvalidDataException Unreadable(string property, int variantType) =>
        new($"{property} has a value type ({variantType}) that SecReview does not read.");
}
