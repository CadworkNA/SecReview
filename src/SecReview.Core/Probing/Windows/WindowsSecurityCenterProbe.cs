using System.Runtime.Versioning;
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
        using ComScope com = ComScope.Enter();

        IWSCProductList* list = null;
        try
        {
            HRESULT created = WSCProductList.CreateInstance(out list);
            if (created.Failed)
            {
                return WindowsError.FromHResult(created.Value, What);
            }

            list->Initialize(kind == SecurityProductKind.Firewall ? ProviderFirewall : ProviderAntivirus);

            int count = list->Count;
            var products = new List<SecurityProduct>(count);
            for (uint index = 0; index < count; index++)
            {
                IWscProduct* product = null;
                list->get_Item(index, &product);
                try
                {
                    products.Add(new SecurityProduct(
                        Bstr.Take(product->ProductName),
                        ToState(product->ProductState),
                        product->SignatureStatus == WSC_SECURITY_SIGNATURE_STATUS.WSC_SECURITY_PRODUCT_UP_TO_DATE));
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

    private static SecurityProductState ToState(WSC_SECURITY_PRODUCT_STATE state) => state switch
    {
        WSC_SECURITY_PRODUCT_STATE.WSC_SECURITY_PRODUCT_STATE_ON => SecurityProductState.On,
        WSC_SECURITY_PRODUCT_STATE.WSC_SECURITY_PRODUCT_STATE_SNOOZED => SecurityProductState.Snoozed,
        WSC_SECURITY_PRODUCT_STATE.WSC_SECURITY_PRODUCT_STATE_EXPIRED => SecurityProductState.Expired,
        _ => SecurityProductState.Off,
    };
}
