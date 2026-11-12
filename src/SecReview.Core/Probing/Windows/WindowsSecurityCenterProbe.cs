using System.Runtime.Versioning;
using Microsoft.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.System.SecurityCenter;

namespace SecReview.Probing.Windows;

/// <summary>
/// Lists the antivirus and firewall products registered with Windows Security Center
/// (<c>IWSCProductList</c>), which is how Windows itself knows about third-party products.
/// </summary>
[SupportedOSPlatform(MinimumWindows.Platform)]
internal sealed class WindowsSecurityCenterProbe : ISecurityCenterProbe
{
    private const string What = "Asking Windows Security Center";

    // WSC_SECURITY_PROVIDER values accepted by IWSCProductList::Initialize.
    private const uint ProviderFirewall = 1;
    private const uint ProviderAntivirus = 4;

    private const string LegacyNamespace = @"ROOT\SecurityCenter2";
    private const string LegacyFirewallClass = "FirewallProduct";

    private readonly IWmiProbe _wmi;

    public WindowsSecurityCenterProbe(IWmiProbe wmi) => _wmi = wmi;

    public unsafe ProbeResult<IReadOnlyList<SecurityProduct>> GetProducts(SecurityProductKind kind)
    {
        // Security Center exists on client editions only. Say so up front instead of relying
        // on whichever error a server edition happens to return.
        if (!IsClientEdition())
        {
            return ProbeFailure.NotSupported("Windows Server has no Security Center.");
        }

        using ComScope com = ComScope.Enter();

        IWSCProductList* list = null;
        try
        {
            HRESULT created = WSCProductList.CreateInstance(out list);
            if (created.Failed)
            {
                return WindowsError.FromHResult(created.Value, What);
            }

            bool antivirus = kind == SecurityProductKind.Antivirus;
            list->Initialize(antivirus ? ProviderAntivirus : ProviderFirewall);

            // A second opinion on which firewalls are not Windows' own (see OtherVendorFirewalls).
            HashSet<string> otherVendors = antivirus ? [] : OtherVendorFirewalls();

            int count = list->Count;
            var products = new List<SecurityProduct>(count);
            for (uint index = 0; index < count; index++)
            {
                IWscProduct* product = null;
                list->get_Item(index, &product);
                try
                {
                    // Only antivirus products have definitions; the value means nothing for a
                    // firewall, so it is not read there.
                    bool? signaturesUpToDate = antivirus
                        ? product->SignatureStatus == WSC_SECURITY_SIGNATURE_STATUS.WSC_SECURITY_PRODUCT_UP_TO_DATE
                        : null;

                    string name = Bstr.Take(product->ProductName);
                    bool builtIn = IsBuiltIn(ReadRemediationPath(product)) && !otherVendors.Contains(name);

                    products.Add(new SecurityProduct(
                        name, ToState(product->ProductState), signaturesUpToDate, builtIn));
                }
                finally
                {
                    product->Release();
                }
            }

            return ProbeResult<IReadOnlyList<SecurityProduct>>.Ok(products);
        }
        catch (Exception exception)
        {
            return WindowsError.FromException(exception, What);
        }
        finally
        {
            if (list is not null)
            {
                list->Release();
            }
        }
    }

    /// <summary>
    /// The program Security Center would open for a product; empty if it gives none or the
    /// read fails. A product that will not say must not make the whole list unreadable.
    /// </summary>
    private static unsafe string ReadRemediationPath(IWscProduct* product)
    {
        try
        {
            return Bstr.Take(product->RemediationPath);
        }
#pragma warning disable CA1031 // Optional detail: any failure just means "not known".
        catch (Exception)
#pragma warning restore CA1031
        {
            return string.Empty;
        }
    }

    /// <summary>
    /// Names of the firewalls the older Security Center WMI class lists. That class lists
    /// products from other vendors only (Windows' own firewall is not in it), so a product
    /// named there is not part of Windows whatever its program path says. Empty if the class
    /// cannot be read; the path then decides alone.
    /// </summary>
    private HashSet<string> OtherVendorFirewalls()
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        ProbeResult<IReadOnlyList<WmiObject>> listed = _wmi.Query(LegacyNamespace, LegacyFirewallClass, ["displayName"]);
        if (listed.IsOk)
        {
            foreach (WmiObject product in listed.Value!)
            {
                if (product.Text("displayName") is { Length: > 0 } name)
                {
                    names.Add(name);
                }
            }
        }

        return names;
    }

    /// <summary>
    /// Whether a product belongs to Windows itself, judged by the program Security Center would
    /// open for it: nothing, the Windows Security app, or something inside the Windows folder.
    /// A product from another vendor normally points at its own program. The display name
    /// cannot be used for this, because it is translated. An unknown path counts as "part of
    /// Windows", the cautious answer: it can cost a PC with another vendor's firewall a failed
    /// check, but never passes a PC whose only firewall is switched off.
    /// </summary>
    internal static bool IsBuiltIn(string remediationPath)
    {
        string path = Environment.ExpandEnvironmentVariables(remediationPath.Trim().Trim('"'));
        if (path.Length == 0 || path.StartsWith("windowsdefender:", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows)
            .TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        return path.StartsWith(windows, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>"WinNT" is a client edition; "ServerNT" and "LanmanNT" are servers.</summary>
    private static bool IsClientEdition()
    {
        try
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\ProductOptions", writable: false);
            return key?.GetValue("ProductType") is not string type ||
                type.Equals("WinNT", StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception exception) when (exception is System.Security.SecurityException
            or UnauthorizedAccessException or IOException)
        {
            // Cannot tell: go on and let Security Center answer for itself.
            return true;
        }
    }

    private static SecurityProductState ToState(WSC_SECURITY_PRODUCT_STATE state) => state switch
    {
        WSC_SECURITY_PRODUCT_STATE.WSC_SECURITY_PRODUCT_STATE_ON => SecurityProductState.On,
        WSC_SECURITY_PRODUCT_STATE.WSC_SECURITY_PRODUCT_STATE_SNOOZED => SecurityProductState.Snoozed,
        WSC_SECURITY_PRODUCT_STATE.WSC_SECURITY_PRODUCT_STATE_EXPIRED => SecurityProductState.Expired,
        _ => SecurityProductState.Off,
    };
}
