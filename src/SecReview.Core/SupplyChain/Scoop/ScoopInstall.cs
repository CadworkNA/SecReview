using System.Text.Json;
using SecReview.Checks;
using SecReview.Probing;

namespace SecReview.SupplyChain.Scoop;

/// <summary>Where a Scoop installation keeps its things, resolved the way Scoop itself does.</summary>
/// <param name="Root">The user's Scoop folder (apps, buckets, shims, persist).</param>
/// <param name="GlobalRoot">The folder of apps installed for all users.</param>
/// <param name="ConfigPath">The settings file in use; null if there is none.</param>
/// <param name="Config">The settings; null if there is no settings file.</param>
internal sealed record ScoopInstall(string Root, string GlobalRoot, string? ConfigPath, JsonElement? Config)
{
    /// <summary>A text setting from the settings file; null if absent or not text.</summary>
    public string? Setting(string name) =>
        Config is { ValueKind: JsonValueKind.Object } config && config.TryGetProperty(name, out JsonElement value) &&
        value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
}

/// <summary>One app installed with Scoop, as its own files describe it.</summary>
/// <param name="Name">The app's name (its folder under <c>apps</c>).</param>
/// <param name="Folder">The folder of the version in use.</param>
/// <param name="Manifest">The manifest it was installed from; null if it could not be read.</param>
/// <param name="Install">Scoop's record of the installation (bucket, hold); null if it could not be read.</param>
/// <param name="Problem">Why one of the two files could not be used.</param>
internal sealed record ScoopApp(string Name, string Folder, JsonElement? Manifest, JsonElement? Install, string? Problem)
{
    public string? Version => Text(Manifest, "version");

    public string? Bucket => Text(Install, "bucket");

    private static string? Text(JsonElement? element, string name) =>
        element is { ValueKind: JsonValueKind.Object } value && value.TryGetProperty(name, out JsonElement property) &&
        property.ValueKind == JsonValueKind.String
            ? property.GetString()
            : null;
}

/// <summary>
/// Finds Scoop and what it has installed, from files only. Scoop is never run. The rules for
/// where things are follow Scoop's own: the <c>SCOOP</c> and <c>SCOOP_GLOBAL</c> variables, then
/// the settings file, then the defaults; a settings file beside a portable Scoop wins.
/// </summary>
internal static class ScoopLocator
{
    /// <summary>The app Scoop installs itself as.</summary>
    private const string CoreApp = "scoop";

    /// <summary>
    /// Scoop's folders and settings; <paramref name="install"/> is null when Scoop is not
    /// installed. Returns the outcome when something needed to tell could not be read.
    /// </summary>
    public static CheckOutcome? Locate(SystemProbes probes, out ScoopInstall? install)
    {
        install = null;

        ProbeResult<string> profile = probes.Environment.Folder(KnownFolder.UserProfile);
        ProbeResult<string> programData = probes.Environment.Folder(KnownFolder.ProgramData);
        if (!profile.IsOk || !programData.IsOk)
        {
            return CheckOutcome.Error("Windows did not say where your user folder is.");
        }

        if (PersistentEnvironment.Read(probes.Registry, "SCOOP", out string? rootVariable, out _) is { } failed1)
        {
            return failed1;
        }

        if (PersistentEnvironment.Read(probes.Registry, "SCOOP_GLOBAL", out string? globalVariable, out _) is { } failed2)
        {
            return failed2;
        }

        if (PersistentEnvironment.Read(probes.Registry, "XDG_CONFIG_HOME", out string? configHome, out _) is { } failed3)
        {
            return failed3;
        }

        // The ordinary settings file first: it may say where the root is.
        string userConfigPath = $@"{configHome ?? profile.Value + @"\.config"}\scoop\config.json";
        JsonElement? config = SettingsFiles.LoadJson(probes.Files, userConfigPath, out string? problem);
        if (problem is not null)
        {
            return CheckOutcome.Error($"Scoop's settings: {problem}");
        }

        string? configPath = config is null ? null : userConfigPath;
        string root = Clean(rootVariable) ?? Clean(Text(config, "root_path")) ?? $@"{profile.Value}\scoop";

        // A settings file inside a portable Scoop's own folder replaces the ordinary one.
        string portablePath = $@"{root}\config.json";
        JsonElement? portable = SettingsFiles.LoadJson(probes.Files, portablePath, out problem);
        if (problem is not null)
        {
            return CheckOutcome.Error($"Scoop's settings: {problem}");
        }

        if (portable is not null)
        {
            (config, configPath) = (portable, portablePath);
        }

        if (!SettingsFiles.FolderExists(probes.Files, $@"{root}\apps"))
        {
            return null;
        }

        string globalRoot = Clean(globalVariable) ?? Clean(Text(config, "global_path")) ?? $@"{programData.Value}\scoop";
        install = new ScoopInstall(root, globalRoot, configPath, config);
        return null;
    }

    /// <summary>
    /// The apps under a root (the user's or the global one), Scoop itself left out. Empty when
    /// the folder is not there; a failure when it is there but cannot be listed.
    /// </summary>
    public static ProbeResult<IReadOnlyList<ScoopApp>> Apps(IFileProbe files, string root)
    {
        ProbeResult<IReadOnlyList<FileEntry>> folders = files.List($@"{root}\apps");
        if (folders.Status == ProbeStatus.NotFound)
        {
            return ProbeResult<IReadOnlyList<ScoopApp>>.Ok([]);
        }

        if (!folders.IsOk)
        {
            return folders.ToFailure();
        }

        var apps = new List<ScoopApp>();
        foreach (FileEntry folder in folders.Value!)
        {
            if (folder.IsDirectory && !folder.Name.Equals(CoreApp, StringComparison.OrdinalIgnoreCase) &&
                App(files, root, folder.Name) is { } app)
            {
                apps.Add(app);
            }
        }

        return ProbeResult<IReadOnlyList<ScoopApp>>.Ok(apps);
    }

    /// <summary>One app by name; null if it is not installed under this root.</summary>
    public static ScoopApp? App(IFileProbe files, string root, string name)
    {
        string? folder = CurrentFolder(files, $@"{root}\apps\{name}");
        if (folder is null)
        {
            return null;
        }

        // Scoop 0.6 renamed both files; it still reads the old names, and so does this.
        JsonElement? manifest = FirstJson(files, folder, ["scoop-manifest.json", "manifest.json"], out string? manifestProblem);
        JsonElement? install = FirstJson(files, folder, ["scoop-install.json", "install.json"], out string? installProblem);
        return new ScoopApp(name, folder, manifest, install, manifestProblem ?? installProblem);
    }

    /// <summary>The version of an app in the user's Scoop; null if Scoop or the app is absent or the version is not readable.</summary>
    public static string? AppVersion(SystemProbes probes, string name) =>
        Locate(probes, out ScoopInstall? install) is null && install is not null
            ? App(probes.Files, install.Root, name)?.Version
            : null;

    /// <summary>
    /// The folder of the version in use: <c>current</c> (a link Scoop keeps), or, where links
    /// are switched off, the newest version folder.
    /// </summary>
    private static string? CurrentFolder(IFileProbe files, string appFolder)
    {
        ProbeResult<IReadOnlyList<FileEntry>> versions = files.List(appFolder);
        if (!versions.IsOk)
        {
            return null;
        }

        if (versions.Value!.Any(v => v.IsDirectory && v.Name.Equals("current", StringComparison.OrdinalIgnoreCase)))
        {
            return $@"{appFolder}\current";
        }

        FileEntry? newest = versions.Value!
            .Where(v => v.IsDirectory && !v.IsLink)
            .OrderByDescending(v => v.LastWrite)
            .FirstOrDefault();
        return newest is null ? null : $@"{appFolder}\{newest.Name}";
    }

    private static JsonElement? FirstJson(IFileProbe files, string folder, string[] names, out string? problem)
    {
        problem = null;
        foreach (string name in names)
        {
            JsonElement? json = SettingsFiles.LoadJson(files, $@"{folder}\{name}", out problem);
            if (json is not null || problem is not null)
            {
                return json;
            }
        }

        return null;
    }

    private static string? Text(JsonElement? element, string name) =>
        element is { ValueKind: JsonValueKind.Object } value && value.TryGetProperty(name, out JsonElement property) &&
        property.ValueKind == JsonValueKind.String
            ? property.GetString()
            : null;

    /// <summary>A folder path without trailing separators; null for an empty one.</summary>
    private static string? Clean(string? path) =>
        string.IsNullOrWhiteSpace(path) ? null : path.Trim().Replace('/', '\\').TrimEnd('\\');
}
