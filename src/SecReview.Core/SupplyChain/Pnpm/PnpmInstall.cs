using System.Text.Json;
using SecReview.Checks;
using SecReview.Config;
using SecReview.Probing;
using SecReview.SupplyChain.Scoop;

namespace SecReview.SupplyChain.Pnpm;

/// <summary>
/// What is known about pnpm on this PC from files alone. pnpm 10 and pnpm 11 or later keep
/// their own settings in different files (<c>rc</c>, an INI file with dashed names, against
/// <c>config.yaml</c> with camel-case names), and each ignores the other's. So the version
/// decides which file counts; when no file records the version, both are read and the result
/// says what it rests on. pnpm is never run.
/// </summary>
/// <param name="Version">The version; null when no file records it.</param>
/// <param name="VersionSource">Where the version was read.</param>
/// <param name="Yaml">The global <c>config.yaml</c> (read by pnpm 11 and later); null if there is none.</param>
/// <param name="Rc">The global <c>rc</c> (pnpm's own settings up to pnpm 10; network settings later); null if there is none.</param>
/// <param name="AuthIni">The global <c>auth.ini</c> (sign-in tokens, pnpm 11 and later); null if there is none.</param>
internal sealed record PnpmInstall(ToolVersion? Version, string? VersionSource, SettingsFile? Yaml, SettingsFile? Rc, SettingsFile? AuthIni)
{
    /// <summary>Whether this pnpm reads <c>config.yaml</c>: true from pnpm 11, false before, null when the version is not known.</summary>
    public bool? ReadsYaml => Version is { } version ? version.Major >= 11 : null;

    /// <summary>The first problem among the files that exist; null when all were read in full.</summary>
    public string? Problem => Yaml?.Problem ?? Rc?.Problem ?? AuthIni?.Problem;
}

internal static class PnpmLocator
{
    /// <summary>The first pnpm with a release cooldown (<c>minimumReleaseAge</c>).</summary>
    public static readonly ToolVersion CooldownFrom = new(10, 16, 0);

    /// <summary>
    /// pnpm on this PC; <paramref name="pnpm"/> is null when no trace of it is found. Returns
    /// the outcome when something needed to tell could not be read.
    /// </summary>
    public static CheckOutcome? Locate(SystemProbes probes, out PnpmInstall? pnpm)
    {
        pnpm = null;
        IFileProbe files = probes.Files;

        ProbeResult<string> roaming = probes.Environment.Folder(KnownFolder.RoamingAppData);
        ProbeResult<string> local = probes.Environment.Folder(KnownFolder.LocalAppData);
        if (!roaming.IsOk || !local.IsOk)
        {
            return CheckOutcome.Error("Windows did not say where your user folders are.");
        }

        if (PersistentEnvironment.Read(probes, "XDG_CONFIG_HOME", out string? configHome, out _) is { } failed)
        {
            return failed;
        }

        // Version: Scoop's record, else the copy installed with npm, else Corepack's folder.
        ToolVersion? version = null;
        string? versionSource = null;
        string? scoopVersion = ScoopLocator.AppVersion(probes, "pnpm");
        if (ToolVersion.Parse(scoopVersion) is { } fromScoop)
        {
            (version, versionSource) = (fromScoop, "Scoop");
        }

        string npmCopy = $@"{roaming.Value}\npm\node_modules\pnpm\package.json";
        if (version is null && SettingsFiles.LoadJson(files, npmCopy, out _) is { ValueKind: JsonValueKind.Object } package &&
            package.TryGetProperty("version", out JsonElement recorded) && recorded.ValueKind == JsonValueKind.String &&
            ToolVersion.Parse(recorded.GetString()) is { } fromNpm)
        {
            (version, versionSource) = (fromNpm, npmCopy);
        }

        string corepack = $@"{local.Value}\node\corepack\v1\pnpm";
        if (version is null && files.List(corepack) is { IsOk: true } corepackVersions)
        {
            ToolVersion? newest = corepackVersions.Value!
                .Where(e => e.IsDirectory)
                .Select(e => ToolVersion.Parse(e.Name))
                .Where(v => v is not null)
                .Max();
            if (newest is not null)
            {
                (version, versionSource) = (newest, corepack);
            }
        }

        string pnpmHome = $@"{local.Value}\pnpm";
        string configFolder = configHome is null ? $@"{pnpmHome}\config" : $@"{configHome.TrimEnd('\\', '/')}\pnpm";

        SettingsFile? yaml = SettingsFiles.Load(files, $@"{configFolder}\config.yaml", SettingsFormat.Yaml);
        SettingsFile? rc = SettingsFiles.Load(files, $@"{configFolder}\rc", SettingsFormat.NpmIni);
        SettingsFile? authIni = SettingsFiles.Load(files, $@"{configFolder}\auth.ini", SettingsFormat.NpmIni);

        bool present = version is not null || scoopVersion is not null || yaml is not null || rc is not null || authIni is not null ||
            SettingsFiles.FolderExists(files, pnpmHome);
        if (present)
        {
            pnpm = new PnpmInstall(version, versionSource, yaml, rc, authIni);
        }

        return null;
    }

    /// <summary>The text of the value in force (the last, where an INI key is written more than once); null if there is none.</summary>
    public static string? Text(ConfigNode? node) => node.InForce()?.Text;

    /// <summary>
    /// A yes/no setting, read the way npm and pnpm read it: true/false as YAML values or as
    /// text, and 1/0. The value in force counts. Null if absent or none of these.
    /// </summary>
    public static bool? Flag(ConfigNode? node) => node.InForce() switch
    {
        { AsBoolean: { } flag } => flag,
        { } scalar => SupplyChain.Flags.Parse(scalar.Text),
        null => null,
    };
}
