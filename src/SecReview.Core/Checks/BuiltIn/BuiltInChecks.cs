using SecReview.Checks.BuiltIn.Ssh;

namespace SecReview.Checks.BuiltIn;

/// <summary>Every check written in code, in the order they are shown.</summary>
public static class BuiltInChecks
{
    public static IReadOnlyList<ICheck> All { get; } =
    [
        new AutomaticLogonCheck(),
        new FirewallCheck(),
        new AntivirusCheck(),
        new DriveEncryptionCheck(),
        new SshKeyPassphraseCheck(),
        new SshKeyStrengthCheck(),
        new SshConfigCheck(),
    ];
}
