using System.Text.Json;
using SecReview.Checks;
using SecReview.Probing;

namespace SecReview.SupplyChain.Editors;

/// <summary>An editor of the VS Code family: where it keeps the user's settings and where it is installed.</summary>
/// <param name="Name">Its name as people write it.</param>
/// <param name="DataFolder">Its folder under the user's roaming application data.</param>
/// <param name="ProgramFolders">Its install folder names, under the user's Programs folder or Program Files.</param>
/// <param name="FollowsVsCodeVersions">Whether its version numbers are VS Code's, so that VS Code's version rules apply.</param>
/// <param name="HasOwnCooldown">Whether it has its own wait setting for extension installs and updates (Cursor).</param>
internal sealed record EditorKind(string Name, string DataFolder, string[] ProgramFolders, bool FollowsVsCodeVersions, bool HasOwnCooldown);

/// <summary>One settings file of an editor that is on this PC.</summary>
/// <param name="Kind">Which editor.</param>
/// <param name="Path">The settings file; the main one, or a profile's.</param>
/// <param name="IsProfile">True for a profile's settings file.</param>
/// <param name="Settings">The settings; null if there is no file (all defaults) or it could not be used.</param>
/// <param name="Problem">Why the file could not be used; null otherwise.</param>
/// <param name="Version">The editor's version; null when no file records it.</param>
internal sealed record EditorSettings(EditorKind Kind, string Path, bool IsProfile, JsonElement? Settings, string? Problem, ToolVersion? Version)
{
    /// <summary>The editor's name, with "(a profile)" for a profile's file.</summary>
    public string Label => IsProfile ? $"{Kind.Name} (a profile)" : Kind.Name;

    /// <summary>A setting's value; null if it is not set.</summary>
    public JsonElement? Get(string name) =>
        Settings is { ValueKind: JsonValueKind.Object } settings && settings.TryGetProperty(name, out JsonElement value) ? value : null;

    public string At(string name) => $"{Path} ({name})";
}

/// <summary>
/// Finds the editors of the VS Code family on this PC and reads their user settings
/// (<c>settings.json</c>, which allows comments). No editor is run. Workspace settings inside
/// a project can add to these; this is the baseline.
/// </summary>
internal static class EditorLocator
{
    public static readonly EditorKind[] Kinds =
    [
        new("VS Code", "Code", ["Microsoft VS Code"], FollowsVsCodeVersions: true, HasOwnCooldown: false),
        new("VS Code Insiders", "Code - Insiders", ["Microsoft VS Code Insiders"], FollowsVsCodeVersions: true, HasOwnCooldown: false),
        new("VSCodium", "VSCodium", ["VSCodium"], FollowsVsCodeVersions: true, HasOwnCooldown: false),
        new("Cursor", "Cursor", ["cursor", "Cursor"], FollowsVsCodeVersions: false, HasOwnCooldown: true),
        new("Windsurf", "Windsurf", ["Windsurf"], FollowsVsCodeVersions: false, HasOwnCooldown: false),
    ];

    /// <summary>
    /// The settings files of every editor found, the main file first and then one per profile.
    /// Empty when no editor is. Returns the outcome when the user folders are not known.
    /// </summary>
    public static CheckOutcome? Locate(SystemProbes probes, out IReadOnlyList<EditorSettings> editors)
    {
        editors = [];
        IFileProbe files = probes.Files;
        ProbeResult<string> roaming = probes.Environment.Folder(KnownFolder.RoamingAppData);
        ProbeResult<string> local = probes.Environment.Folder(KnownFolder.LocalAppData);
        ProbeResult<string> programFiles = probes.Environment.Folder(KnownFolder.ProgramFiles);
        if (!roaming.IsOk || !local.IsOk || !programFiles.IsOk)
        {
            return CheckOutcome.Error("Windows did not say where your user folders are.");
        }

        // These editors keep their data under the folder VSCODE_APPDATA names, when that is set.
        if (PersistentEnvironment.Read(probes, "VSCODE_APPDATA", out string? moved, out _) is { } failed)
        {
            return failed;
        }

        string data = string.IsNullOrWhiteSpace(moved) ? roaming.Value! : moved.Trim().Replace('/', '\\').TrimEnd('\\');

        var found = new List<EditorSettings>();
        foreach (EditorKind kind in Kinds)
        {
            string user = $@"{data}\{kind.DataFolder}\User";
            if (!SettingsFiles.FolderExists(files, user))
            {
                continue;
            }

            ToolVersion? version = null;
            foreach (string folder in kind.ProgramFolders)
            {
                foreach (string root in (string[])[$@"{local.Value}\Programs", programFiles.Value!])
                {
                    version ??= Version(files, $@"{root}\{folder}");
                }
            }

            found.Add(Load(files, kind, $@"{user}\settings.json", isProfile: false, version));

            ProbeResult<IReadOnlyList<FileEntry>> profiles = files.List($@"{user}\profiles");
            if (profiles.IsOk)
            {
                foreach (FileEntry profile in profiles.Value!.Where(p => p.IsDirectory))
                {
                    string path = $@"{user}\profiles\{profile.Name}\settings.json";
                    if (files.ReadText(path).Status != ProbeStatus.NotFound)
                    {
                        found.Add(Load(files, kind, path, isProfile: true, version));
                    }
                }
            }
            else if (profiles.Status != ProbeStatus.NotFound)
            {
                // Profiles that cannot be listed are settings that were not looked at.
                found.Add(new EditorSettings(kind, $@"{user}\profiles", IsProfile: true, null, $"The profiles of {kind.Name} could not be read.", version));
            }
        }

        editors = found;
        return null;
    }

    private static EditorSettings Load(IFileProbe files, EditorKind kind, string path, bool isProfile, ToolVersion? version)
    {
        JsonElement? settings = SettingsFiles.LoadJsonSettings(files, path, out string? problem);
        if (problem is null && settings is { ValueKind: not JsonValueKind.Object })
        {
            problem = "settings.json: could not evaluate (line 1): it is not a set of named settings.";
        }

        return new EditorSettings(kind, path, isProfile, problem is null ? settings : null, problem, version);
    }

    /// <summary>The version in the editor's own package.json; null if the editor is not installed there.</summary>
    private static ToolVersion? Version(IFileProbe files, string install)
    {
        // Newer builds keep the app's files one folder down, in a folder named after the build.
        var paths = new List<string> { $@"{install}\resources\app\package.json" };
        if (files.List(install) is { IsOk: true } entries)
        {
            paths.AddRange(entries.Value!.Where(e => e.IsDirectory).Select(e => $@"{install}\{e.Name}\resources\app\package.json"));
        }

        foreach (string path in paths)
        {
            if (SettingsFiles.LoadJson(files, path, out _) is { ValueKind: JsonValueKind.Object } package &&
                package.TryGetProperty("version", out JsonElement version) && version.ValueKind == JsonValueKind.String)
            {
                return ToolVersion.Parse(version.GetString());
            }
        }

        return null;
    }
}
