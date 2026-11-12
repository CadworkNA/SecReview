using System.Text.Json;
using SecReview.Checks;
using SecReview.Config;
using SecReview.Probing;

namespace SecReview.SupplyChain.Cooldowns;

/// <summary>The user's folders that package managers keep their settings under.</summary>
internal sealed record UserFolders(string Profile, string Roaming, string Local, string ProgramData, string ProgramFiles);

/// <summary>One place a tool reads its release wait from: a settings file and the path of keys inside it.</summary>
internal sealed record CooldownSource(SettingsFile File, IReadOnlyList<string> KeyPath);

/// <summary>What is known about a tool on this PC from files alone.</summary>
/// <param name="Version">Its version; null when no file records it.</param>
/// <param name="VersionSource">Where the version was read.</param>
/// <param name="Sources">The settings files that exist, in the order the tool prefers them.</param>
internal sealed record ToolState(ToolVersion? Version, string? VersionSource, IReadOnlyList<CooldownSource> Sources);

/// <summary>
/// The check every package manager with a release wait shares: the tool must wait at least a
/// week before installing a newly published version. Each tool brings where it keeps the
/// setting, how it writes a length of time, the version that introduced the setting, and what
/// it does when nothing is set. The tool is never run; where no file records its version,
/// the result says what it rests on. A project can still override a user-level setting; the
/// check is about the baseline.
/// </summary>
public abstract class CooldownCheck : ICheck
{
    private const string Item = "Wait before installing new releases";
    private const string Expected = "7 days or more";

    protected CooldownCheck(string id, string tool)
    {
        Tool = tool;
        Definition = new CheckDefinition(id, CheckCategory.SupplyChain, Severity.High, AdminNeed.No, CheckScope.User);
    }

    public CheckDefinition Definition { get; }

    /// <summary>The tool's name as people write it: "npm", "Yarn".</summary>
    protected string Tool { get; }

    /// <summary>The first version of the tool that has the setting.</summary>
    private protected abstract ToolVersion MinimumVersion { get; }

    /// <summary>The persistent environment variable that overrides the files; null if the tool has none.</summary>
    private protected virtual string? Variable => null;

    /// <summary>
    /// The tool on this PC; <paramref name="state"/> is null when no trace of it is found.
    /// </summary>
    private protected abstract CheckOutcome? Locate(SystemProbes probes, UserFolders folders, out ToolState? state);

    /// <summary>The length of time a value in a settings file stands for.</summary>
    private protected abstract Cooldown Read(ConfigScalar value);

    /// <summary>The length of time the environment variable's text stands for; by default read like a text value in a file.</summary>
    private protected virtual Cooldown ReadVariable(string text) => Read(new ConfigScalar(text, ScalarKind.Text, 0));

    /// <summary>
    /// What the tool does when nothing is set: its built-in wait if it has one, words for the
    /// finding, and the summary when the usual sentence would not be true.
    /// </summary>
    private protected virtual (TimeSpan? Wait, string Words, string? Summary) WhenNotSet(ToolVersion? version) =>
        (null, $"Not set ({Tool} does not wait by default)", null);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        SystemProbes probes = context.Probes;

        if (Folders(probes) is not { } folders)
        {
            return CheckOutcome.Error("Windows did not say where your user folders are.");
        }

        if (Locate(probes, folders, out ToolState? state) is { } failed)
        {
            return failed;
        }

        if (state is null)
        {
            return CheckOutcome.NotApplicable($"{Tool} is not installed.");
        }

        if (state.Version is { } old && old < MinimumVersion)
        {
            return CheckOutcome.Fail(
                $"{Tool} {old} cannot wait before installing new releases; update {Tool}.",
                Finding.Problem($"{Tool} version", old.ToString(), $"{MinimumVersion} or later", state.VersionSource));
        }

        // The variable wins over the files; among the files, the first that sets the value.
        Cooldown? cooldown = null;
        string? source = null;
        if (Variable is { } variable)
        {
            if (PersistentEnvironment.Read(probes, variable, out string? text, out string? variableSource) is { } unread)
            {
                return unread;
            }

            if (text is not null)
            {
                (cooldown, source) = (ReadVariable(text), variableSource);
            }
        }

        if (cooldown is null)
        {
            foreach (CooldownSource candidate in state.Sources)
            {
                // A file that could not be read may set the value, and it would win over the
                // files after it: without it the answer is not known.
                if (candidate.File.Root is not { } root)
                {
                    return CheckOutcome.Error(candidate.File.Problem ?? $"{candidate.File.Name} could not be read.");
                }

                if (root.Find([.. candidate.KeyPath]) is not { } node)
                {
                    continue;
                }

                source = candidate.File.At(node);
                if (candidate.File.Single(node) is not { } scalar)
                {
                    return CheckOutcome.Error($"{candidate.File.Name}: could not evaluate (line {node.Line}): the release wait is not a single value.");
                }

                source = candidate.File.At(scalar);
                cooldown = Read(scalar);
                break;
            }
        }

        var findings = new List<Finding>();
        if (cooldown is not { } wait)
        {
            (TimeSpan? builtIn, string words, string? summary) = WhenNotSet(state.Version);
            findings.Add(Finding.Problem(Item, words, Expected));
            AddVersion(state, findings);
            return CheckOutcome.Fail(
                summary ??
                (builtIn is { } length
                    ? $"{Tool} waits only its default of {Wording.Duration(length)} before installing a new release."
                    : $"{Tool} installs new package versions the moment they are published."),
                findings);
        }

        switch (wait.Kind)
        {
            case CooldownKind.Disabled:
                return CheckOutcome.Fail($"{Tool}'s wait for new releases is switched off.", Finding.Problem(Item, "Switched off", Expected, source));
            case CooldownKind.AbsoluteDate:
                return CheckOutcome.Fail(
                    $"{Tool}'s release cut-off is a fixed date, which stops protecting as time passes.",
                    Finding.Problem(Item, "A fixed date", Expected, source));
            case CooldownKind.Invalid:
                return CheckOutcome.Error($"{Tool}'s release wait is not written in a form {Tool} understands ({source}).");
        }

        string duration = wait.Length == TimeSpan.Zero ? "Switched off" : Wording.Duration(wait.Length);
        if (wait.Length < Durations.Week)
        {
            findings.Add(Finding.Problem(Item, duration, Expected, source));
            AddVersion(state, findings);
            return CheckOutcome.Fail(
                wait.Length == TimeSpan.Zero
                    ? $"{Tool}'s wait for new releases is switched off."
                    : $"{Tool} waits only {duration} before installing a new release.",
                findings);
        }

        findings.Add(Finding.Ok(Item, duration, Expected, source));
        AddVersion(state, findings);
        return CheckOutcome.Pass(
            state.Version is null
                ? $"{Tool} is set to wait {duration}; this holds from {Tool} {MinimumVersion}, and the installed version could not be read."
                : $"{Tool} waits {duration} before installing a new release.",
            findings);
    }

    private void AddVersion(ToolState state, List<Finding> findings) => findings.Add(state.Version is { } version
        ? Finding.Ok($"{Tool} version", version.ToString(), $"{MinimumVersion} or later", state.VersionSource)
        : Finding.Note($"{Tool} version", $"Not readable; the setting is honoured from {Tool} {MinimumVersion}"));

    private static UserFolders? Folders(SystemProbes probes)
    {
        ProbeResult<string> profile = probes.Environment.Folder(KnownFolder.UserProfile);
        ProbeResult<string> roaming = probes.Environment.Folder(KnownFolder.RoamingAppData);
        ProbeResult<string> local = probes.Environment.Folder(KnownFolder.LocalAppData);
        ProbeResult<string> programData = probes.Environment.Folder(KnownFolder.ProgramData);
        ProbeResult<string> programFiles = probes.Environment.Folder(KnownFolder.ProgramFiles);
        return profile.IsOk && roaming.IsOk && local.IsOk && programData.IsOk && programFiles.IsOk
            ? new UserFolders(profile.Value!, roaming.Value!, local.Value!, programData.Value!, programFiles.Value!)
            : null;
    }

    /// <summary>The settings files among the candidates that exist, each with the key path the value is under.</summary>
    private protected static List<CooldownSource> Existing(
        IFileProbe files, SettingsFormat format, IReadOnlyList<string> keyPath, params ReadOnlySpan<string> paths)
    {
        var sources = new List<CooldownSource>(paths.Length);
        foreach (string path in paths)
        {
            if (SettingsFiles.Load(files, path, format) is { } file)
            {
                sources.Add(new CooldownSource(file, keyPath));
            }
        }

        return sources;
    }

    /// <summary>The "version" of a package.json-style file; null if the file is absent or has none.</summary>
    private protected static ToolVersion? JsonVersion(IFileProbe files, string path) =>
        SettingsFiles.LoadJson(files, path, out _) is { ValueKind: JsonValueKind.Object } json &&
        json.TryGetProperty("version", out JsonElement version) && version.ValueKind == JsonValueKind.String
            ? ToolVersion.Parse(version.GetString())
            : null;
}
