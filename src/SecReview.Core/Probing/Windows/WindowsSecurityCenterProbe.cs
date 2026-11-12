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

                    products.Add(new SecurityProduct(
                        Bstr.Take(product->ProductName), ToState(product->ProductState), signaturesUpToDate));
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
