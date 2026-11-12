using System.Globalization;
using SecReview.Checks;
using SecReview.Config;

namespace SecReview.SupplyChain.Pnpm;

/// <summary>
/// pnpm must wait at least a week before it installs a newly published package version
/// (<c>minimumReleaseAge</c>, in minutes). The setting only counts in the file the installed
/// pnpm reads: <c>config.yaml</c> from pnpm 11, the INI file <c>rc</c> (as
/// <c>minimum-release-age</c>) for pnpm 10. pnpm 11 and later wait one day when nothing is
/// set; pnpm 10 does not wait at all; older versions cannot. A project can still override
/// the setting; this check is about the baseline.
/// </summary>
public sealed class PnpmCooldownCheck : ICheck
{
    public const string Id = "sc.pnpm.cooldown";

    internal const string YamlSetting = "minimumReleaseAge";
    internal const string IniSetting = "minimum-release-age";
    internal const string Variable = "pnpm_config_minimum_release_age";

    private const string Item = "Wait before installing new releases";
    private const string Expected = "7 days or more";

    private static readonly TimeSpan Minute = TimeSpan.FromMinutes(1);

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.High, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (PnpmLocator.Locate(context.Probes, out PnpmInstall? pnpm) is { } failed)
        {
            return failed;
        }

        if (pnpm is null)
        {
            return CheckOutcome.NotApplicable("pnpm is not installed.");
        }

        // pnpm takes the setting from its own variable before any file (pnpm 11 and later).
        if (PersistentEnvironment.Read(context.Probes, Variable, out string? fromVariable, out string? variableSource) is { } unreadVariable)
        {
            return unreadVariable;
        }

        if (pnpm.Version is { } old && old < PnpmLocator.CooldownFrom)
        {
            return CheckOutcome.Fail(
                $"pnpm {old} cannot wait before installing new releases; update pnpm.",
                Finding.Problem("pnpm version", old.ToString(), $"{PnpmLocator.CooldownFrom} or later", pnpm.VersionSource));
        }

        // pnpm 10 reads the INI file; pnpm 11 and later read the YAML file. Unknown version: the YAML file, as current pnpm does.
        bool usesYaml = pnpm.ReadsYaml ?? true;

        // The variable decides when it is set: pnpm 11 and later read it before any file.
        if (fromVariable is not null && usesYaml)
        {
            if (!long.TryParse(fromVariable.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out long fromEnvironment) ||
                Durations.FromNumber(fromEnvironment, Minute) is not { Kind: CooldownKind.Relative } set)
            {
                return CheckOutcome.Error($"pnpm's release wait in {variableSource} is not a number of minutes.");
            }

            bool enough = set.Length >= Durations.Week;
            string wait = set.Length == TimeSpan.Zero ? "Switched off" : Wording.Duration(set.Length);
            var byVariable = new List<Finding>
            {
                enough ? Finding.Ok(Item, wait, Expected, variableSource) : Finding.Problem(Item, wait, Expected, variableSource),
            };
            AddVersion(pnpm, byVariable);
            return enough
                ? CheckOutcome.Pass($"pnpm waits {wait} before installing a new release.", byVariable)
                : CheckOutcome.Fail(
                    set.Length == TimeSpan.Zero
                        ? "pnpm's wait for new releases is switched off."
                        : $"pnpm waits only {wait} before installing a new release.",
                    byVariable);
        }

        SettingsFile? file = usesYaml ? pnpm.Yaml : pnpm.Rc;
        ConfigNode? written = file?.Root?[usesYaml ? YamlSetting : IniSetting];

        var findings = new List<Finding>();
        if (written is null)
        {
            // Nothing in the file that counts. If that file could not be read, "not set" is not known.
            if (file?.Problem is { } problem)
            {
                return CheckOutcome.Error(problem);
            }

            // Set, but in the file this pnpm does not read: the most likely mistake, so it is named.
            SettingsFile? other = usesYaml ? pnpm.Rc : pnpm.Yaml;
            if (other?.Root?[usesYaml ? IniSetting : YamlSetting] is { } misplaced)
            {
                findings.Add(Finding.Note(
                    "Set in a file this pnpm ignores",
                    usesYaml ? "rc is only read for this by pnpm 10" : "config.yaml is only read by pnpm 11 and later",
                    other.At(misplaced)));
            }

            string unset = usesYaml ? "Not set (pnpm waits 1 day by default)" : "Not set (pnpm 10 does not wait by default)";
            findings.Insert(0, Finding.Problem(Item, unset, Expected));
            AddVersion(pnpm, findings);
            return CheckOutcome.Fail(
                usesYaml
                    ? "pnpm waits only its default of 1 day before installing a new release."
                    : "pnpm installs new package versions the moment they are published.",
                findings);
        }

        // A number in YAML; INI has no numbers, so digits there.
        ConfigScalar? inForce = file!.Single(written);
        long? minutes = inForce switch
        {
            ConfigScalar { AsNumber: { } number } => number,
            ConfigScalar { Kind: ScalarKind.Text } text when !usesYaml &&
                long.TryParse(text.Text, NumberStyles.None, CultureInfo.InvariantCulture, out long parsed) => parsed,
            _ => null,
        };
        if (minutes is null || Durations.FromNumber(minutes.Value, Minute) is not { Kind: CooldownKind.Relative } cooldown)
        {
            return CheckOutcome.Error($"{file!.Name}: could not evaluate (line {written.Line}): the release wait is not a number of minutes.");
        }

        string source = file!.At(inForce!);
        string length = Wording.Duration(cooldown.Length);
        if (cooldown.Length < Durations.Week)
        {
            findings.Add(Finding.Problem(Item, cooldown.Length == TimeSpan.Zero ? "Switched off" : length, Expected, source));
            AddVersion(pnpm, findings);
            return CheckOutcome.Fail(
                cooldown.Length == TimeSpan.Zero
                    ? "pnpm's wait for new releases is switched off."
                    : $"pnpm waits only {length} before installing a new release.",
                findings);
        }

        findings.Add(Finding.Ok(Item, length, Expected, source));

        // Settings that take the teeth out of the wait.
        bool weakened = false;
        if (usesYaml && PnpmLocator.Flag(file.Root![YamlSetting + "Strict"]) == false)
        {
            weakened = true;
            findings.Add(Finding.Problem("Strict wait", "Off: too-new versions are still installed when nothing else fits", "On", file.At(file.Root[YamlSetting + "Strict"]!)));
        }

        if (file.Root![usesYaml ? YamlSetting + "Exclude" : IniSetting + "-exclude"] is ConfigList { Items.Count: > 0 } exclusions)
        {
            findings.Add(Finding.Note(
                "Packages exempt from the wait", exclusions.Items.Count.ToString(CultureInfo.InvariantCulture), file.At(exclusions)));
        }

        AddVersion(pnpm, findings);
        if (weakened)
        {
            return CheckOutcome.Fail($"pnpm waits {length}, but not strictly: a too-new version can still be installed.", findings);
        }

        return CheckOutcome.Pass(
            pnpm.Version is null
                ? $"pnpm is set to wait {length}; the installed version could not be read, and pnpm 10 would ignore this file."
                : $"pnpm waits {length} before installing a new release.",
            findings);
    }

    private static void AddVersion(PnpmInstall pnpm, List<Finding> findings) => findings.Add(pnpm.Version is { } version
        ? Finding.Ok("pnpm version", version.ToString(), $"{PnpmLocator.CooldownFrom} or later", pnpm.VersionSource)
        : Finding.Note("pnpm version", "Not readable; config.yaml counts from pnpm 11, rc for pnpm 10"));
}
