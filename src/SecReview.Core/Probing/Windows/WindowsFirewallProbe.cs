using System.Runtime.Versioning;
using Windows.Win32.Foundation;
using Windows.Win32.NetworkManagement.WindowsFirewall;

namespace SecReview.Probing.Windows;

/// <summary>
/// Reads the effective Windows Firewall state through <c>INetFwPolicy2</c>, which reflects
/// Group Policy and needs no administrator rights.
/// </summary>
[SupportedOSPlatform(MinimumWindows.Platform)]
internal sealed class WindowsFirewallProbe : IFirewallProbe
{
    private const string What = "Reading the Windows Firewall state";

    private static readonly (FirewallProfiles Profile, NET_FW_PROFILE_TYPE2 Native)[] Profiles =
    [
        (FirewallProfiles.Domain, NET_FW_PROFILE_TYPE2.NET_FW_PROFILE2_DOMAIN),
        (FirewallProfiles.Private, NET_FW_PROFILE_TYPE2.NET_FW_PROFILE2_PRIVATE),
        (FirewallProfiles.Public, NET_FW_PROFILE_TYPE2.NET_FW_PROFILE2_PUBLIC),
    ];

    public unsafe ProbeResult<FirewallState> GetState()
    {
        using ComScope com = ComScope.Enter();

        INetFwPolicy2* policy = null;
        try
        {
            HRESULT created = NetFwPolicy2.CreateInstance(out policy);
            if (created.Failed)
            {
                return WindowsError.FromHResult(created.Value, What);
            }

            var states = new List<FirewallProfileState>(Profiles.Length);
            foreach ((FirewallProfiles profile, NET_FW_PROFILE_TYPE2 native) in Profiles)
            {
                bool enabled = policy->get_FirewallEnabled(native) != VARIANT_BOOL.VARIANT_FALSE;
                bool blocks = policy->get_DefaultInboundAction(native) == NET_FW_ACTION.NET_FW_ACTION_BLOCK;
                states.Add(new FirewallProfileState(profile, enabled, blocks));
            }

            // The native profile bits are the same as FirewallProfiles.
            var active = (FirewallProfiles)policy->CurrentProfileTypes &
                (FirewallProfiles.Domain | FirewallProfiles.Private | FirewallProfiles.Public);

            return ProbeResult<FirewallState>.Ok(new FirewallState(states, active));
        }
        catch (Exception exception)
        {
            return WindowsError.FromException(exception, What);
        }
        finally
        {
            if (policy is not null)
            {
                policy->Release();
            }
        }
    }
}
