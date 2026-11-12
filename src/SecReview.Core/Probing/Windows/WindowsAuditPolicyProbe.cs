using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Windows.Win32;
using Windows.Win32.Security.Authentication.Identity;

namespace SecReview.Probing.Windows;

/// <summary>Reads the advanced audit policy with <c>AuditQuerySystemPolicy</c>.</summary>
[SupportedOSPlatform(MinimumWindows.Platform)]
internal sealed class WindowsAuditPolicyProbe : IAuditPolicyProbe
{
    private const string What = "Reading the audit policy";

    // POLICY_AUDIT_EVENT_SUCCESS and POLICY_AUDIT_EVENT_FAILURE.
    private const uint SuccessBit = 1;
    private const uint FailureBit = 2;

    public unsafe ProbeResult<IReadOnlyDictionary<Guid, AuditSetting>> GetSubcategories(
        IReadOnlyList<Guid> subcategories)
    {
        ArgumentNullException.ThrowIfNull(subcategories);
        if (subcategories.Count == 0)
        {
            return ProbeResult<IReadOnlyDictionary<Guid, AuditSetting>>.Ok(new Dictionary<Guid, AuditSetting>());
        }

        AUDIT_POLICY_INFORMATION* policy = null;
        try
        {
            Guid[] ids = [.. subcategories];
            if (!PInvoke.AuditQuerySystemPolicy(ids, out policy))
            {
                return WindowsError.FromWin32(Marshal.GetLastPInvokeError(), What);
            }

            var settings = new Dictionary<Guid, AuditSetting>(ids.Length);
            for (int index = 0; index < ids.Length; index++)
            {
                uint information = policy[index].AuditingInformation;
                AuditSetting setting = AuditSetting.None;
                if ((information & SuccessBit) != 0)
                {
                    setting |= AuditSetting.Success;
                }

                if ((information & FailureBit) != 0)
                {
                    setting |= AuditSetting.Failure;
                }

                settings[policy[index].AuditSubCategoryGuid] = setting;
            }

            return ProbeResult<IReadOnlyDictionary<Guid, AuditSetting>>.Ok(settings);
        }
        catch (Exception exception)
        {
            return WindowsError.FromException(exception, What);
        }
        finally
        {
            if (policy is not null)
            {
                PInvoke.AuditFree(policy);
            }
        }
    }
}
