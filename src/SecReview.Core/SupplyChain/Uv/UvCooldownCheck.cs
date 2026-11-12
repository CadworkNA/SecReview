using SecReview.Checks;
using SecReview.Config;

namespace SecReview.SupplyChain.Uv;

/// <summary>
/// uv must wait at least a week before it installs a newly published package version
/// (<c>exclude-newer</c> as a length of time). uv has no such delay by default. A fixed date
/// does not count: it protects on the day it is written and goes stale after. The setting is
/// read where uv reads it: the <c>UV_EXCLUDE_NEWER</c> variable, then the user's settings
/// file, then the PC's. A project can still override it; this check is about the baseline.
/// </summary>
public sealed class UvCooldownCheck : ICheck
{
    public const string Id = "sc.uv.cooldown";

    internal const string Setting = "exclude-newer";
    internal const string Variable = "UV_EXCLUDE_NEWER";

    private const string Item = "Wait before installing new releases";
    private const string Expected = "7 days or more";

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.High, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (UvLocator.Locate(context.Probes, out UvInstall? uv) is { } failed)
        {
            return failed;
        }

        if (uv is null)
        {
            return CheckOutcome.NotApplicable("uv is not installed.");
        }

        if (PersistentEnvironment.Read(context.Probes.Registry, Variable, out string? fromVariable, out string? variableSource) is { } unread)
        {
            return unread;
        }

        string? written;
        string? source;
        if (fromVariable is not null)
        {
            (written, source) = (fromVariable, variableSource);
        }
        else if (uv.Find(Setting) is { } found)
        {
            written = found.Value switch
            {
                ConfigScalar { Kind: ScalarKind.Text or ScalarKind.Other } scalar => scalar.Text,
                ConfigScalar { AsBoolean: false } => "false",
                _ => null,
            };
            source = found.File.At(found.Value);
            if (written is null)
            {
                return CheckOutcome.Error($"{found.File.Name}: could not evaluate (line {found.Value.Line}): exclude-newer is not a length of time or a date.");
            }
        }
        else
        {
            // Nothing found. If a settings file could not be read, "not set" is not known.
            return uv.Problem is { } problem
                ? CheckOutcome.Error(problem)
                : CheckOutcome.Fail(
                    "uv installs new package versions the moment they are published.",
                    Finding.Problem(Item, "Not set (uv has no delay by default)", Expected));
        }

        Cooldown cooldown = Durations.ParseUv(written);
        switch (cooldown.Kind)
        {
            case CooldownKind.Disabled:
                return CheckOutcome.Fail("uv's wait for new releases is switched off.", Finding.Problem(Item, "Switched off", Expected, source));
            case CooldownKind.AbsoluteDate:
                return CheckOutcome.Fail(
                    "uv's release cut-off is a fixed date, which stops protecting as time passes.",
                    Finding.Problem(Item, "A fixed date", Expected, source));
            case CooldownKind.Invalid:
                return CheckOutcome.Error($"uv's exclude-newer setting is not a length of time or a date ({source}).");
        }

        string length = Wording.Duration(cooldown.Length);
        if (cooldown.Length < Durations.Week)
        {
            return CheckOutcome.Fail($"uv waits only {length} before installing a new release.", Finding.Problem(Item, length, Expected, source));
        }

        // A length of time is only understood from uv 0.9.17 on.
        var findings = new List<Finding> { Finding.Ok(Item, length, Expected, source) };
        AddExceptions(uv, findings);
        if (uv.Version is { } version)
        {
            if (version < UvLocator.RelativeCooldownFrom)
            {
                findings[0] = Finding.Problem(Item, $"{length}, but uv {version} does not understand it", Expected, source);
                findings.Add(Finding.Problem("uv version", version.ToString(), $"{UvLocator.RelativeCooldownFrom} or later", uv.VersionSource));
                return CheckOutcome.Fail($"uv {version} is too old for a wait written as a length of time; update uv.", findings);
            }

            findings.Add(Finding.Ok("uv version", version.ToString(), $"{UvLocator.RelativeCooldownFrom} or later", uv.VersionSource));
            return CheckOutcome.Pass($"uv waits {length} before installing a new release.", findings);
        }

        // No file records the version of a stand-alone uv. A required-version line makes an
        // older uv refuse to run, which settles the question without knowing the version.
        bool pinned = uv.Find("required-version") is { Value: ConfigScalar { Kind: ScalarKind.Text } required } &&
            MinimumOf(required.Text) is { } minimum && minimum >= UvLocator.RelativeCooldownFrom;
        findings.Add(pinned
            ? Finding.Ok("uv version", "Not readable; required-version rules out an older uv", $"{UvLocator.RelativeCooldownFrom} or later")
            : Finding.Note(
                "uv version",
                $"Not readable. Honoured from uv {UvLocator.RelativeCooldownFrom}; add required-version = \">={UvLocator.RelativeCooldownFrom}\" to uv.toml to be sure"));
        return CheckOutcome.Pass(
            pinned
                ? $"uv waits {length} before installing a new release."
                : $"uv is set to wait {length}; this holds from uv {UvLocator.RelativeCooldownFrom}, and the installed version could not be read.",
            findings);
    }

    /// <summary>Packages that the settings exempt from the wait, or give a shorter one: listed, so they are a choice and not a surprise.</summary>
    private static void AddExceptions(UvInstall uv, List<Finding> findings)
    {
        const int Most = 10;
        if (uv.Find("exclude-newer-package") is not { Value: ConfigMap exceptions } found)
        {
            return;
        }

        int listed = 0;
        foreach ((string package, ConfigNode value) in exceptions.Entries)
        {
            Cooldown cooldown = Durations.ParseUv(value switch
            {
                ConfigScalar { AsBoolean: false } => "false",
                ConfigScalar scalar => scalar.Text,
                _ => null,
            });
            if (cooldown.Kind == CooldownKind.Relative && cooldown.Length >= Durations.Week)
            {
                continue;
            }

            if (++listed > Most)
            {
                findings.Add(Finding.Note("More exceptions", $"{exceptions.Entries.Count - Most} more packages", found.File.At(found.Value)));
                return;
            }

            findings.Add(Finding.Note(
                $"Exception for {package}",
                cooldown.Kind switch
                {
                    CooldownKind.Disabled => "No wait",
                    CooldownKind.AbsoluteDate => "A fixed date",
                    CooldownKind.Relative => Wording.Duration(cooldown.Length),
                    _ => "Not understood",
                },
                found.File.At(value)));
        }
    }

    /// <summary>The lowest version a "&gt;=1.2.3" (or "==1.2.3") requirement allows; null for anything else.</summary>
    internal static ToolVersion? MinimumOf(string requirement)
    {
        foreach (string part in requirement.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            if (part.StartsWith(">=", StringComparison.Ordinal) || part.StartsWith("==", StringComparison.Ordinal) ||
                part.StartsWith("~=", StringComparison.Ordinal))
            {
                return ToolVersion.Parse(part[2..]);
            }
        }

        return null;
    }
}
