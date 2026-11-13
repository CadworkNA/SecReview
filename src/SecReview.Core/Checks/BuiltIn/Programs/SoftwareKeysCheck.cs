using System.Globalization;
using SecReview.Probing;

namespace SecReview.Checks.BuiltIn.Programs;

/// <summary>
/// Programs keep the settings they share between all users under HKLM\SOFTWARE, where only
/// administrators can write. Programs that run with high rights read them too, so a key under
/// it that standard users can change lets them alter what those programs do. The check looks
/// at each product's key and the keys directly inside it,
/// for 64-bit and 32-bit programs; keys under Microsoft's own key belong to Windows and are
/// counted, not judged.
/// </summary>
public sealed class SoftwareKeysCheck : ICheck
{
    public const string Id = "harden.software-keys";

    internal const string SoftwareKey = "SOFTWARE";
    internal const string Software32Key = @"SOFTWARE\WOW6432Node";

    /// <summary>The most keys read. A PC with more gets "could not check", not a partial answer.</summary>
    internal const int MaximumKeys = 5000;

    /// <summary>Keys that are not a product's: the 32-bit view is read on its own, and the registered components have their own check.</summary>
    private static readonly string[] NotDescended = ["WOW6432Node", "Classes"];

    public CheckDefinition Definition { get; } = new(
        Id, CheckCategory.Hardening, Severity.Low, AdminNeed.ForFullDetail, CheckScope.Machine, KeepsAdministratorAnswer: true);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        IRegistryProbe registry = context.Probes.Registry;
        var judge = new ProgramJudge(context.Probes.Access);
        var report = new EntryReport("settings key", "settings keys", context.IsElevated);
        int read = 0;
        int partOfWindows = 0;

        foreach (string root in (string[])[SoftwareKey, Software32Key])
        {
            ProbeResult<IReadOnlyList<string>> makers = registry.GetSubKeyNames(RegistryRoot.LocalMachine, root);
            if (makers.Status == ProbeStatus.NotFound && root != SoftwareKey)
            {
                continue;
            }

            if (!makers.IsOk)
            {
                return ProbeOutcomes.FromFailure(makers, "the settings programs keep for the whole PC");
            }

            foreach (string maker in makers.Value!)
            {
                context.Cancellation.ThrowIfCancellationRequested();
                string key = $@"{root}\{maker}";
                bool windows = maker.Equals("Microsoft", StringComparison.OrdinalIgnoreCase);
                if (root == SoftwareKey && maker.Equals("WOW6432Node", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                // A key users can change hands that down to what is inside it: one row is enough.
                if (Add(key) || NotDescended.Contains(maker, StringComparer.OrdinalIgnoreCase))
                {
                    continue;
                }

                ProbeResult<IReadOnlyList<string>> products = registry.GetSubKeyNames(RegistryRoot.LocalMachine, key);
                if (!products.IsOk)
                {
                    if (products.Status != ProbeStatus.NotFound)
                    {
                        report.Unread($@"HKLM\{key}", products.Detail ?? "Its keys could not be listed", products.Status == ProbeStatus.AccessDenied);
                    }

                    continue;
                }

                foreach (string product in products.Value!)
                {
                    Add($@"{key}\{product}");
                    if (read > MaximumKeys)
                    {
                        return CheckOutcome.Error(string.Create(
                            CultureInfo.InvariantCulture, $"More than {MaximumKeys} settings keys are stored; they were not read."));
                    }
                }

                // Judges one key; true when standard users can change it.
                bool Add(string path)
                {
                    read++;
                    Verdict verdict = judge.Key(RegistryRoot.LocalMachine, path);
                    string item = $@"HKLM\{path}";
                    if (verdict.Kind == VerdictKind.Changeable && windows)
                    {
                        partOfWindows++;
                        report.Fine();
                    }
                    else if (verdict.Kind == VerdictKind.Changeable)
                    {
                        report.Problem(item, $"{verdict.Who} can change it", item);
                    }
                    else if (verdict.Kind == VerdictKind.Unknown)
                    {
                        report.Unread(item, verdict.NeedsAdministrator ? "Reading its permissions needs administrator rights" : verdict.Reason ?? "Its permissions could not be read", verdict.NeedsAdministrator);
                    }
                    else if (verdict.Kind == VerdictKind.Protected)
                    {
                        report.Fine();
                    }

                    return verdict.Kind == VerdictKind.Changeable;
                }
            }
        }

        if (partOfWindows > 0)
        {
            report.Note("Part of Windows", string.Create(
                CultureInfo.InvariantCulture,
                $"{partOfWindows} {(partOfWindows == 1 ? "key" : "keys")} under Microsoft's own key can be changed by standard users; not judged"));
        }

        return report.Outcome("No program keeps settings for the whole PC.");
    }
}
