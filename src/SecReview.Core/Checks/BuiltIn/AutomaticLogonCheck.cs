using SecReview.Probing;

namespace SecReview.Checks.BuiltIn;

/// <summary>
/// Windows must not sign a user in automatically at start-up, and no sign-in password may be
/// left in the registry. The password value itself is never read, only whether it exists.
/// </summary>
public sealed class AutomaticLogonCheck : ICheck
{
    public const string Id = "logon.automatic";

    internal const string WinlogonKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    internal const string EnabledValue = "AutoAdminLogon";
    internal const string PasswordValue = "DefaultPassword";

    private const string Source = @"HKLM\" + WinlogonKey;

    public CheckDefinition Definition { get; } = new(Id, CheckCategory.Access, Severity.High);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        IRegistryProbe registry = context.Probes.Registry;

        ProbeResult<RegistryValue> enabledValue =
            registry.GetValue(RegistryRoot.LocalMachine, WinlogonKey, EnabledValue);
        if (!enabledValue.IsOk && enabledValue.Status != ProbeStatus.NotFound)
        {
            return ProbeOutcomes.FromFailure(enabledValue, "the automatic sign-in setting");
        }

        ProbeResult<IReadOnlyList<string>> names = registry.GetValueNames(RegistryRoot.LocalMachine, WinlogonKey);
        if (!names.IsOk && names.Status != ProbeStatus.NotFound)
        {
            return ProbeOutcomes.FromFailure(names, "the automatic sign-in setting");
        }

        // A missing value means the feature was never set up.
        bool enabled = enabledValue.IsOk && IsOn(enabledValue.Value!);
        bool passwordStored = names.IsOk &&
            names.Value!.Contains(PasswordValue, StringComparer.OrdinalIgnoreCase);

        List<Finding> findings =
        [
            enabled
                ? Finding.Problem("Automatic sign-in", "On", "Off", $@"{Source}\{EnabledValue}")
                : Finding.Ok("Automatic sign-in", "Off", "Off", $@"{Source}\{EnabledValue}"),
            passwordStored
                ? Finding.Problem("Password kept in the registry", "Yes", "No", $@"{Source}\{PasswordValue}")
                : Finding.Ok("Password kept in the registry", "No", "No", $@"{Source}\{PasswordValue}"),
        ];

        if (enabled)
        {
            return CheckOutcome.Fail("Windows signs in automatically at start-up.", findings);
        }

        if (passwordStored)
        {
            return CheckOutcome.Fail(
                "Automatic sign-in is off, but a sign-in password is still stored in the registry.", findings);
        }

        return CheckOutcome.Pass("Automatic sign-in is off.", findings);
    }

    /// <summary>Windows writes "1" as text; a number 1 is accepted too.</summary>
    private static bool IsOn(RegistryValue value) => value.Type switch
    {
        RegistryValueType.Text => value.Text.Trim() == "1",
        RegistryValueType.Number => value.Number == 1,
        _ => false,
    };
}
