using SecReview.Catalogue;
using SecReview.Checks;
using SecReview.Checks.BuiltIn;
using SecReview.Checks.BuiltIn.Ssh;

namespace SecReview.Scanning;

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

    public static ScanResult Create(TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(clock);

        CheckTexts texts = CheckCatalogue.Texts;
        DateTimeOffset now = clock.GetUtcNow();

        return new ScanResult(
            [.. CheckCatalogue.Checks.Select(check =>
            {
                string id = check.Definition.Id;
                CheckOutcome outcome = Outcomes.TryGetValue(id, out CheckOutcome? made)
                    ? made
                    : CheckOutcome.Pass(texts[id].TitlePass + ".");
                return new ScannedCheck(
                    check.Definition, texts[id], new CheckResult(id, outcome, now, Elevated: false, TimeSpan.FromMilliseconds(40)));
            })],
            now,
            Elevated: false);
    }
}
