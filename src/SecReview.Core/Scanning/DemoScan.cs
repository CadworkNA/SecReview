using SecReview.Catalogue;
using SecReview.Checks;
using SecReview.Checks.BuiltIn;

namespace SecReview.Scanning;

/// <summary>
/// A made-up scan result that shows every kind of outcome. Used to look at, test and
/// photograph the window without reading, or weakening, a real PC.
/// </summary>
public static class DemoScan
{
    public static ScanResult Create(TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(clock);

        CheckTexts texts = CheckTexts.Load();
        DateTimeOffset now = clock.GetUtcNow();
        Dictionary<string, CheckDefinition> definitions =
            BuiltInChecks.All.ToDictionary(c => c.Definition.Id, c => c.Definition);

        ScannedCheck Scanned(string id, CheckOutcome outcome) => new(
            definitions[id], texts[id], new CheckResult(id, outcome, now, Elevated: false, TimeSpan.FromMilliseconds(40)));

        return new ScanResult(
        [
            Scanned(AutomaticLogonCheck.Id, CheckOutcome.Pass(
                "Automatic sign-in is off.",
                Finding.Ok("Automatic sign-in", "Off", "Off"),
                Finding.Ok("Password kept in the registry", "No", "No"))),
            Scanned(FirewallCheck.Id, CheckOutcome.Fail(
                "Windows Firewall is off for the Public network.",
                Finding.Ok("Domain network", "On", "On"),
                Finding.Ok("Private network (in use)", "On", "On"),
                Finding.Problem("Public network", "Off", "On"))),
            Scanned(AntivirusCheck.Id, CheckOutcome.Error(
                "Asking Windows Security Center failed: the service did not answer (0x800706BA)")),
            Scanned(DriveEncryptionCheck.Id, CheckOutcome.NeedsAdmin(
                "Windows does not confirm that C: is fully protected. The administrator check reads the details.",
                Finding.Problem("C: (Windows)", "Not fully protected", "On"),
                Finding.Ok("D:", "On", "On"))),
        ],
        now,
        Elevated: false);
    }
}
