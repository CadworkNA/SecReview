using SecReview.Checks.BuiltIn.Programs;
using SecReview.Checks.BuiltIn.Ssh;

namespace SecReview.Checks.BuiltIn;

/// <summary>Every check written in code, in the order they are shown: by category, most important first.</summary>
public static class BuiltInChecks
{
    public static IReadOnlyList<ICheck> All { get; } =
    [
        // Access
        new ScreenLockCheck(),
        new AutomaticLogonCheck(),
        new BuiltInAccountsCheck(),
        new PasswordManagerCheck(),
        new SshKeyPassphraseCheck(),
        new SshKeyStrengthCheck(),
        new SshConfigCheck(),

        // Updates
        new AutomaticUpdatesCheck(),
        new RecentUpdatesCheck(),
        new RestartCheck(),
        new WindowsSupportedCheck(),
        new Updates.SecReviewUpdateCheck(),

        // Firewall and sharing
        new FirewallCheck(),
        new RemoteDesktopCheck(),
        new RemoteServicesCheck(),
        new SharedFoldersCheck(),
        new FirewallProgramsCheck(),
        new ProxyCheck(),

        // System integrity
        new DriveEncryptionCheck(),
        new AntivirusCheck(),
        new DefenderCheck(),
        new AllowedAppsCheck(),
        new UacCheck(),
        new SecureBootCheck(),
        new TpmCheck(),
        new MemoryIntegrityCheck(),
        new BootOptionsCheck(),
        new StartupProgramsCheck(),
        new ServiceProgramsCheck(),
        new SearchPathCheck(),
        new ProgramFoldersCheck(),
        new RegisteredComponentsCheck(),
        new ScheduledTasksCheck(),

        // Hardening (the rest of this category is written as rules)
        new RevocationCheck(),
        new SoftwareKeysCheck(),
    ];
}
