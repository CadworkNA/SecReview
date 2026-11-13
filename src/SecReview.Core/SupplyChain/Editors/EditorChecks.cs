using System.Globalization;
using System.Text.Json;
using SecReview.Checks;
using SecReview.Probing;

namespace SecReview.SupplyChain.Editors;

/// <summary>
/// Editors of the VS Code family should wait a week before installing an extension update
/// (<c>extensions.autoUpdateDelay</c>, in hours, from VS Code 1.125; Cursor has
/// <c>extensions.installCooldownHours</c>), or not update extensions by themselves at all. An
/// extension runs with all the user's rights, and a taken-over extension reaches every PC
/// within hours otherwise. VS Code's delay covers updates, not first installs; the result says so.
/// </summary>
public sealed class EditorUpdatesCheck : ICheck
{
    public const string Id = "sc.editor.updates";

    internal static readonly ToolVersion DelayFrom = new(1, 125, 0);

    private const long WeekInHours = 168;
    private const string Expected = "168 hours or more, or automatic updates off";

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.Medium, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        SystemProbes probes = context.Probes;

        if (EditorLocator.Locate(probes, out IReadOnlyList<EditorSettings> all) is { } failed)
        {
            return failed;
        }

        // Extension updates are an application-wide setting: the main settings file decides.
        EditorSettings[] editors = [.. all.Where(e => !e.IsProfile && (e.Kind.FollowsVsCodeVersions || e.Kind.HasOwnCooldown))];
        if (editors.Length == 0)
        {
            return CheckOutcome.NotApplicable("No editor with a wait for extension updates is installed.");
        }

        var findings = new List<Finding>();
        var weak = new List<string>();
        var versionUnread = new List<string>();
        string? unreadable = null;

        foreach (EditorSettings editor in editors)
        {
            if (editor.Problem is not null)
            {
                unreadable ??= editor.Problem;
                continue;
            }

            string item = $"{editor.Kind.Name}: wait before extension updates";
            bool versionMatters = editor.Kind.FollowsVsCodeVersions && editor.Version is null;

            // VS Code itself can be managed by policy, which wins over the settings file.
            string? source = null;
            long? delay = null;
            bool? automatic = null;
            if (editor.Kind.Name == "VS Code")
            {
                if (Policy(probes, out delay, out automatic) is { } unread)
                {
                    return unread;
                }

                source = delay is null ? null : PolicySource;
            }

            // The word "off" is only understood from the version that has the delay; before it, only false is.
            bool knowsTheWord = !(editor.Kind.FollowsVsCodeVersions && editor.Version is { } known && known < DelayFrom);
            string automaticSource = automatic is null ? editor.At("extensions.autoUpdate") : PolicySource;
            bool byWord = automatic is null && editor.Get("extensions.autoUpdate") is { ValueKind: JsonValueKind.String };
            automatic ??= AutomaticUpdates(editor.Get("extensions.autoUpdate"), knowsTheWord);
            if (automatic == false)
            {
                findings.Add(Finding.Ok($"{editor.Kind.Name}: automatic extension updates", "Off", Expected, automaticSource));
                if (byWord && versionMatters)
                {
                    versionUnread.Add(editor.Kind.Name);
                    findings.Add(Finding.Note($"{editor.Kind.Name} version", $"Not readable; \"off\" is understood from {DelayFrom}"));
                }

                continue;
            }

            string setting = editor.Kind.HasOwnCooldown ? "extensions.installCooldownHours" : "extensions.autoUpdateDelay";
            if (delay is null && editor.Get(setting) is { } written)
            {
                if (written.ValueKind != JsonValueKind.Number || !written.TryGetInt64(out long hours) || hours < 0)
                {
                    return CheckOutcome.Error($"{editor.Kind.Name}'s {setting} setting is not a number of hours ({editor.At(setting)}).");
                }

                (delay, source) = (hours, editor.At(setting));
            }

            // Before 1.125 the setting does not exist: updates arrive at once whatever the file says.
            if (editor.Kind.FollowsVsCodeVersions && editor.Version is { } version && version < DelayFrom)
            {
                weak.Add(editor.Kind.Name);
                findings.Add(Finding.Problem(item, $"None: {editor.Kind.Name} {version} cannot delay them", $"{editor.Kind.Name} {DelayFrom} or later", source));
                continue;
            }

            if (delay is { } set && set >= WeekInHours)
            {
                findings.Add(Finding.Ok(item, Hours(set), Expected, source));
                if (versionMatters)
                {
                    versionUnread.Add(editor.Kind.Name);
                    findings.Add(Finding.Note($"{editor.Kind.Name} version", $"Not readable; the wait is honoured from {DelayFrom}"));
                }
            }
            else
            {
                weak.Add(editor.Kind.Name);
                findings.Add(Finding.Problem(
                    item, delay is { } few ? Hours(few) : "Not set (the editor's default is a few hours at most)", Expected, source));
            }
        }

        if (weak.Count > 0)
        {
            return CheckOutcome.Fail(
                $"{Wording.JoinWithAnd(weak)} {(weak.Count == 1 ? "installs" : "install")} extension updates within hours of their release.", findings);
        }

        if (unreadable is not null)
        {
            return CheckOutcome.Error(unreadable);
        }

        findings.Add(Finding.Note("What the wait covers", "Updates of extensions you have; a newly installed extension is not delayed"));
        return CheckOutcome.Pass(
            versionUnread.Count > 0
                ? $"The extension update settings of {Wording.JoinWithAnd(versionUnread)} are in order; they hold from version {DelayFrom}, and the installed version could not be read."
                : editors.Length == 1
                    ? $"{editors[0].Kind.Name} waits a week before installing extension updates, or does not update them by itself."
                    : "Your editors wait a week before installing extension updates, or do not update them by themselves.",
            findings);
    }

    private const string PolicySource = "Your organisation's policy for VS Code";

    /// <summary>Whether extensions update by themselves: true unless the setting is false, or "off" where the editor knows that word.</summary>
    private static bool AutomaticUpdates(JsonElement? setting, bool knowsTheWord) => setting switch
    {
        { ValueKind: JsonValueKind.False } => false,
        { ValueKind: JsonValueKind.String } text when knowsTheWord && string.Equals(text.GetString(), "off", StringComparison.Ordinal) => false,
        _ => true,
    };

    /// <summary>
    /// VS Code's policy values, the PC's before the user's; null when not set. A policy may be
    /// stored as a number or as text, and either is read.
    /// </summary>
    private static CheckOutcome? Policy(SystemProbes probes, out long? delay, out bool? automatic)
    {
        (delay, automatic) = (null, null);
        const string Key = @"SOFTWARE\Policies\Microsoft\VSCode";
        foreach (RegistryRoot root in (RegistryRoot[])[RegistryRoot.LocalMachine, RegistryRoot.CurrentUser])
        {
            foreach (string name in (string[])["ExtensionsAutoUpdateDelay", "ExtensionsAutoUpdate"])
            {
                ProbeResult<RegistryValue> read = probes.Registry.GetValue(root, Key, name);
                if (read.Status == ProbeStatus.NotFound)
                {
                    continue;
                }

                if (!read.IsOk)
                {
                    return ProbeOutcomes.FromFailure(read, "VS Code's policy");
                }

                RegistryValue value = read.Value!;
                string text = value.Type == RegistryValueType.Text ? value.Text.Trim() : string.Empty;
                if (name == "ExtensionsAutoUpdateDelay")
                {
                    delay ??= value.Type == RegistryValueType.Number && value.Number >= 0
                        ? value.Number
                        : long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out long hours) ? hours : null;
                }
                else if (value.Type == RegistryValueType.Number)
                {
                    automatic ??= value.Number != 0;
                }
                else if (text.Length > 0)
                {
                    automatic ??= !(text.Equals("off", StringComparison.OrdinalIgnoreCase) || text.Equals("false", StringComparison.OrdinalIgnoreCase));
                }
            }
        }

        return null;
    }

    private static string Hours(long hours) => hours == 1 ? "1 hour" : string.Create(CultureInfo.InvariantCulture, $"{hours} hours");
}

/// <summary>
/// Editors of the VS Code family must keep the protections that stand between opening a
/// folder and running its code: extension signature checks, Workspace Trust (which also
/// holds back a folder's tasks until the folder is trusted), and no blanket approval for
/// what the built-in AI agent does. Every editor found and every profile is looked at.
/// </summary>
public sealed class EditorSettingsCheck : ICheck
{
    public const string Id = "sc.editor.settings";

    /// <summary>Setting, the JSON value that is a problem, what it is, and the words for it.</summary>
    private static readonly (string Name, string Bad, string Item, string Found, string Expected)[] Rules =
    [
        ("extensions.verifySignature", "false", "Extension signature checks", "Off", "On"),
        ("security.workspace.trust.enabled", "false", "Workspace Trust", "Off: every folder's code may run", "On"),
        ("chat.tools.global.autoApprove", "true", "AI agent actions", "All approved without asking", "Ask first"),
        ("chat.tools.autoApprove", "true", "AI agent actions", "All approved without asking", "Ask first"),
    ];

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.High, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (EditorLocator.Locate(context.Probes, out IReadOnlyList<EditorSettings> editors) is { } failed)
        {
            return failed;
        }

        if (editors.Count == 0)
        {
            return CheckOutcome.NotApplicable("No editor of the VS Code family is installed.");
        }

        var problems = new List<Finding>();
        foreach (EditorSettings editor in editors)
        {
            foreach ((string name, string bad, string item, string found, string expected) in Rules)
            {
                // Two settings may say the same thing (an older and a newer name); one row is enough.
                string row = $"{editor.Label}: {Wording.LowerFirst(item)}";
                if (editor.Get(name) is { } value && Text(value).Equals(bad, StringComparison.OrdinalIgnoreCase) &&
                    !problems.Exists(p => p.Item == row && p.Source?.StartsWith(editor.Path, StringComparison.Ordinal) == true))
                {
                    problems.Add(Finding.Problem(row, found, expected, editor.At(name)));
                }
            }
        }

        if (problems.Count > 0)
        {
            return CheckOutcome.Fail(
                problems.Count == 1
                    ? $"{problems[0].Item}: {Wording.LowerFirst(problems[0].Found)}."
                    : $"Your editors have {problems.Count} protections switched off.",
                problems);
        }

        // Nothing found. If a settings file could not be read, "nothing wrong" is not known.
        if (editors.FirstOrDefault(e => e.Problem is not null)?.Problem is { } problem)
        {
            return CheckOutcome.Error(problem);
        }

        string names = Wording.JoinWithAnd([.. editors.Select(e => e.Kind.Name).Distinct()]);
        return CheckOutcome.Pass(
            $"{names}: signature checks and Workspace Trust are on, and the AI agent asks before it acts.",
            Finding.Ok("Extension signature checks", "On", "On"),
            Finding.Ok("Workspace Trust", "On", "On"),
            Finding.Ok("AI agent actions", "Ask first", "Ask first"));
    }

    /// <summary>A setting's value as the word it is written as: true, false, or the text.</summary>
    private static string Text(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.True => "true",
        JsonValueKind.False => "false",
        JsonValueKind.String => value.GetString() ?? string.Empty,
        _ => string.Empty,
    };
}
