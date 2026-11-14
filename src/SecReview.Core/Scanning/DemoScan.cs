using SecReview.Catalogue;
using SecReview.Checks;
using SecReview.Checks.BuiltIn;
using SecReview.Checks.BuiltIn.Ssh;

using SecReview.Settings;

namespace SecReview.Scanning;

/// <summary>Which state of the window the made-up results show.</summary>
public enum DemoState
{
    /// <summary>Every kind of outcome.</summary>
    Mixed,

    /// <summary>Nothing to fix.</summary>
    AllPass,

    /// <summary>As <see cref="Mixed"/>, on the very first start.</summary>
    FirstRun,

    /// <summary>The scan itself could not run.</summary>
    Failed,

    /// <summary>The last results on screen while a new scan runs.</summary>
    Loading,

    /// <summary>As <see cref="Mixed"/>, with two checks ignored.</summary>
    Ignored,

    /// <summary>As <see cref="Ignored"/>; an automated run then opens every dialog once.</summary>
    Dialogs,
}

/// <summary>
/// A made-up scan result that shows every kind of outcome. Used to look at, test and
/// photograph the window without reading, or weakening, a real PC.
/// </summary>
public static class DemoScan
{
    /// <summary>The checks with a made-up outcome of their own. Every other check simply passes.</summary>
    private static readonly Dictionary<string, CheckOutcome> Outcomes = new()
    {
        [AutomaticLogonCheck.Id] = CheckOutcome.Pass(
            "Automatic sign-in is off.",
            Finding.Ok("Automatic sign-in", "Off", "Off"),
            Finding.Ok("Password kept in the registry", "No", "No")),
        [FirewallCheck.Id] = CheckOutcome.Fail(
            "Windows Firewall is off for the Public network.",
            Finding.Ok("Domain network", "On", "On"),
            Finding.Ok("Private network (in use)", "On", "On"),
            Finding.Problem("Public network", "Off", "On")),
        [AntivirusCheck.Id] = CheckOutcome.Error(
            "Asking Windows Security Center failed: the service did not answer (0x800706BA)"),
        [DriveEncryptionCheck.Id] = CheckOutcome.NeedsAdmin(
            "Windows does not confirm that C: is fully protected. The administrator check reads the details.",
            Finding.Problem("C: (Windows)", "Not fully protected", "On"),
            Finding.Ok("D:", "On", "On")),
        [SshKeyPassphraseCheck.Id] = CheckOutcome.Fail(
            "id_rsa has no passphrase.",
            Finding.Ok("id_ed25519", "Passphrase", "Passphrase"),
            Finding.Problem("id_rsa", "No passphrase", "Passphrase")),
        [SshConfigCheck.Id] = CheckOutcome.NotApplicable("No SSH client settings file."),
    };

    /// <summary>What the administrator checks read about drive encryption: more than an ordinary scan can.</summary>
    private static readonly CheckOutcome AdministratorDriveEncryption = CheckOutcome.Fail(
        "BitLocker is suspended on C:.",
        Finding.Problem("C: (Windows)", "Suspended", "On"),
        Finding.Ok("D:", "On", "On"));

    /// <summary>The names the command line knows the states by.</summary>
    public static IReadOnlyDictionary<string, DemoState> StateNames { get; } = new Dictionary<string, DemoState>(StringComparer.Ordinal)
    {
        ["mixed"] = DemoState.Mixed,
        ["all-pass"] = DemoState.AllPass,
        ["first-run"] = DemoState.FirstRun,
        ["failed"] = DemoState.Failed,
        ["loading"] = DemoState.Loading,
        ["ignored"] = DemoState.Ignored,
        ["dialogs"] = DemoState.Dialogs,
    };

    /// <summary>The checks the <see cref="DemoState.Ignored"/> state leaves out, with made-up reasons.</summary>
    public static IReadOnlyList<IgnoredCheck> Ignored(TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(clock);
        DateTimeOffset since = clock.GetUtcNow().AddDays(-12);
        return
        [
            new IgnoredCheck(SshKeyPassphraseCheck.Id, "Lab key for the build bench, replaced every week", since),
            new IgnoredCheck(AutomaticLogonCheck.Id, "Kiosk PC in the workshop", since),
        ];
    }

    public static ScanResult Create(TimeProvider clock, DemoState state = DemoState.Mixed)
    {
        ArgumentNullException.ThrowIfNull(clock);

        CheckTexts texts = CheckCatalogue.Texts;
        DateTimeOffset now = clock.GetUtcNow();

        return new ScanResult(
            [.. CheckCatalogue.Checks.Select(check =>
            {
                string id = check.Definition.Id;
                CheckOutcome outcome = state != DemoState.AllPass && Outcomes.TryGetValue(id, out CheckOutcome? made)
                    ? made
                    : CheckOutcome.Pass(texts[id].TitlePass + ".");
                return new ScannedCheck(
                    check.Definition, texts[id], new CheckResult(id, outcome, now, Elevated: false, TimeSpan.FromMilliseconds(40)))
                {
                    // An answer the administrator checks gave yesterday, kept beside today's.
                    Administrator = state != DemoState.AllPass && id == DriveEncryptionCheck.Id
                        ? new CheckResult(id, AdministratorDriveEncryption, now.AddDays(-1), Elevated: true, TimeSpan.FromMilliseconds(900))
                        : null,
                };
            })],
            now,
            Elevated: false);
    }
}
