using System.Text.Json;
using SecReview.Checks;
using SecReview.Config;
using SecReview.Probing;
using SecReview.SupplyChain.Scoop;

namespace SecReview.SupplyChain.Uv;

/// <summary>
/// What is known about uv on this PC from files alone: whether it is there, its version when
/// a file records it, and the settings files it reads, highest priority first. uv is never run.
/// </summary>
/// <param name="Version">The version; null when no file records it (a stand-alone uv has none).</param>
/// <param name="VersionSource">Where the version was read.</param>
/// <param name="Files">The settings files uv reads for the user, in the order uv prefers them.</param>
/// <param name="StateFolder">Where uv keeps its own data (credentials, tools).</param>
internal sealed record UvInstall(ToolVersion? Version, string? VersionSource, IReadOnlyList<SettingsFile> Files, string StateFolder)
{
    /// <summary>The first settings file that sets a key, with its value; null if none does.</summary>
    public (SettingsFile File, ConfigNode Value)? Find(string key)
    {
        foreach (SettingsFile file in Files)
        {
            if (file.Root?[key] is { } value)
            {
                return (file, value);
            }
        }

        return null;
    }

    /// <summary>
    /// Why the value of a key is not known, if it is not: a settings file that could not be read
    /// comes before the first file that sets the key (or no file sets it). Such a file may set
    /// the key itself and would win. Null when the first file to set the key can be trusted to be it.
    /// </summary>
    public string? BlockedBefore(string key)
    {
        foreach (SettingsFile file in Files)
        {
            if (file.Root is null)
            {
                return file.Problem ?? $"{file.Name} could not be read.";
            }

            if (file.Root[key] is not null)
            {
                return null;
            }
        }

        return null;
    }

    /// <summary>The first problem among the settings files; null when all were read in full.</summary>
    public string? Problem => Files.FirstOrDefault(f => f.Problem is not null)?.Problem;
}

internal static class UvLocator
{
    /// <summary>The first uv that accepts a relative cooldown such as "7 days".</summary>
    public static readonly ToolVersion RelativeCooldownFrom = new(0, 9, 17);

    /// <summary>
    /// uv on this PC; <paramref name="uv"/> is null when no trace of it is found. Returns the
    /// outcome when something needed to tell could not be read.
    /// </summary>
    public static CheckOutcome? Locate(SystemProbes probes, out UvInstall? uv)
    {
        uv = null;
        IFileProbe files = probes.Files;

        ProbeResult<string> profile = probes.Environment.Folder(KnownFolder.UserProfile);
        ProbeResult<string> roaming = probes.Environment.Folder(KnownFolder.RoamingAppData);
        ProbeResult<string> local = probes.Environment.Folder(KnownFolder.LocalAppData);
        ProbeResult<string> programData = probes.Environment.Folder(KnownFolder.ProgramData);
        if (!profile.IsOk || !roaming.IsOk || !local.IsOk || !programData.IsOk)
        {
            return CheckOutcome.Error("Windows did not say where your user folders are.");
        }

        // uv keeps its data in %APPDATA%\uv, or in a "data" folder inside it left by old versions.
        string uvFolder = $@"{roaming.Value}\uv";
        string stateFolder = SettingsFiles.FolderExists(files, $@"{uvFolder}\data") ? $@"{uvFolder}\data" : uvFolder;

        // Version: the stand-alone installer's receipt, else Scoop's record. Neither may exist.
        ToolVersion? version = null;
        string? versionSource = null;
        string receiptPath = $@"{local.Value}\uv\uv-receipt.json";
        if (SettingsFiles.LoadJson(files, receiptPath, out _) is { ValueKind: JsonValueKind.Object } receipt &&
            receipt.TryGetProperty("version", out JsonElement recorded) && recorded.ValueKind == JsonValueKind.String &&
            ToolVersion.Parse(recorded.GetString()) is { } fromReceipt)
        {
            (version, versionSource) = (fromReceipt, receiptPath);
        }

        string? scoopVersion = ScoopLocator.AppVersion(probes, "uv");
        if (version is null && ToolVersion.Parse(scoopVersion) is { } fromScoop)
        {
            (version, versionSource) = (fromScoop, "Scoop");
        }

        bool present =
            version is not null || scoopVersion is not null ||
            SettingsFiles.Exists(files, $@"{profile.Value}\.local\bin", "uv.exe") ||
            SettingsFiles.FolderExists(files, uvFolder);
        if (!present)
        {
            return null;
        }

        // UV_CONFIG_FILE replaces every settings file uv would otherwise find.
        if (PersistentEnvironment.Read(probes, "UV_CONFIG_FILE", out string? configFile, out _) is { } failed)
        {
            return failed;
        }

        if (PersistentEnvironment.Read(probes, "UV_NO_CONFIG", out string? noConfig, out _) is { } failedToo)
        {
            return failedToo;
        }

        var settings = new List<SettingsFile>(2);
        if (configFile is not null)
        {
            settings.Add(
                SettingsFiles.Load(files, configFile, SettingsFormat.Toml) ??
                new SettingsFile(configFile, null, "The settings file named by UV_CONFIG_FILE does not exist."));
        }
        else if (noConfig is null || Flags.Parse(noConfig) == false)
        {
            foreach (string path in (string[])[$@"{uvFolder}\uv.toml", $@"{programData.Value}\uv\uv.toml"])
            {
                if (SettingsFiles.Load(files, path, SettingsFormat.Toml) is { } file)
                {
                    settings.Add(file);
                }
            }
        }

        uv = new UvInstall(version, versionSource, settings, stateFolder);
        return null;
    }
}
