using System.Globalization;
using SecReview.Checks;
using SecReview.Config;
using SecReview.Probing;
using SecReview.SupplyChain.Scoop;

namespace SecReview.SupplyChain.Cooldowns;

/// <summary>
/// npm: <c>min-release-age</c>, in days, in the user's <c>.npmrc</c> (or the file named by
/// <c>NPM_CONFIG_USERCONFIG</c>), then npm's global <c>npmrc</c>. From npm 11.10.
/// </summary>
public sealed class NpmCooldownCheck : CooldownCheck
{
    public const string Id = "sc.npm.cooldown";

    public NpmCooldownCheck()
        : base(Id, "npm")
    {
    }

    private protected override ToolVersion MinimumVersion => new(11, 10, 0);

    private protected override string? Variable => "NPM_CONFIG_MIN_RELEASE_AGE";

    private protected override Cooldown Read(ConfigScalar value) =>
        long.TryParse(value.Text.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out long days)
            ? Durations.FromNumber(days, TimeSpan.FromDays(1))
            : Cooldown.Invalid;

    private protected override CheckOutcome? Locate(SystemProbes probes, UserFolders folders, out ToolState? state)
    {
        state = null;
        IFileProbe files = probes.Files;

        if (PersistentEnvironment.Read(probes.Registry, "NPM_CONFIG_USERCONFIG", out string? userConfig, out _) is { } failed)
        {
            return failed;
        }

        // npm ships inside Node.js; a newer npm installed with "npm install -g npm" sits in the user's folder and wins.
        ToolVersion? version = null;
        string? versionSource = null;
        string?[] copies =
        [
            $@"{folders.Roaming}\npm\node_modules\npm\package.json",
            $@"{folders.ProgramFiles}\nodejs\node_modules\npm\package.json",
            ScoopCopy(probes, "nodejs"),
            ScoopCopy(probes, "nodejs-lts"),
        ];
        foreach (string? copy in copies)
        {
            if (copy is not null && JsonVersion(files, copy) is { } found)
            {
                (version, versionSource) = (found, copy);
                break;
            }
        }

        List<CooldownSource> sources = Existing(
            files, SettingsFormat.NpmIni, ["min-release-age"], userConfig ?? $@"{folders.Profile}\.npmrc", $@"{folders.Roaming}\npm\etc\npmrc");

        if (version is not null || sources.Count > 0 || SettingsFiles.FolderExists(files, $@"{folders.ProgramFiles}\nodejs"))
        {
            state = new ToolState(version, versionSource, sources);
        }

        return null;
    }

    /// <summary>The npm that comes with a Node.js installed through Scoop; null if there is none.</summary>
    private static string? ScoopCopy(SystemProbes probes, string app) =>
        ScoopLocator.Locate(probes, out ScoopInstall? scoop) is null && scoop is not null &&
        ScoopLocator.App(probes.Files, scoop.Root, app) is { } node
            ? $@"{node.Folder}\node_modules\npm\package.json"
            : null;
}

/// <summary>
/// Yarn (version 2 and later): <c>npmMinimalAgeGate</c> in the user's <c>.yarnrc.yml</c>,
/// written like "7d"; a bare number is minutes. From Yarn 4.10; Yarn 4.15 and later wait one
/// day when nothing is set. Yarn's version is chosen per project, so it cannot be read here.
/// </summary>
public sealed class YarnCooldownCheck : CooldownCheck
{
    public const string Id = "sc.yarn.cooldown";

    public YarnCooldownCheck()
        : base(Id, "Yarn")
    {
    }

    private protected override ToolVersion MinimumVersion => new(4, 10, 0);

    private protected override string? Variable => "YARN_NPM_MINIMAL_AGE_GATE";

    private protected override Cooldown Read(ConfigScalar value) => value.AsNumber is { } minutes
        ? Durations.FromNumber(minutes, TimeSpan.FromMinutes(1))
        : Durations.ParseShort(value.Text, TimeSpan.FromMinutes(1));

    private protected override (TimeSpan? Wait, string Words) WhenNotSet(ToolVersion? version) =>
        (null, "Not set (Yarn 4.15 and later wait 1 day; earlier versions do not wait)");

    private protected override CheckOutcome? Locate(SystemProbes probes, UserFolders folders, out ToolState? state)
    {
        List<CooldownSource> sources = Existing(probes.Files, SettingsFormat.Yaml, ["npmMinimalAgeGate"], $@"{folders.Profile}\.yarnrc.yml");
        state = sources.Count > 0 || SettingsFiles.FolderExists(probes.Files, $@"{folders.Profile}\.yarn")
            ? new ToolState(null, null, sources)
            : null;
        return null;
    }
}

/// <summary>Bun: <c>minimumReleaseAge</c>, in seconds, under <c>[install]</c> in the user's <c>.bunfig.toml</c>. From Bun 1.3.</summary>
public sealed class BunCooldownCheck : CooldownCheck
{
    public const string Id = "sc.bun.cooldown";

    public BunCooldownCheck()
        : base(Id, "Bun")
    {
    }

    private protected override ToolVersion MinimumVersion => new(1, 3, 0);

    private protected override Cooldown Read(ConfigScalar value) => value.AsNumber is { } seconds
        ? Durations.FromNumber(seconds, TimeSpan.FromSeconds(1))
        : Cooldown.Invalid;

    private protected override CheckOutcome? Locate(SystemProbes probes, UserFolders folders, out ToolState? state)
    {
        List<CooldownSource> sources = Existing(
            probes.Files, SettingsFormat.Toml, ["install", "minimumReleaseAge"], $@"{folders.Profile}\.bunfig.toml");
        state = sources.Count > 0 || SettingsFiles.FolderExists(probes.Files, $@"{folders.Profile}\.bun")
            ? new ToolState(null, null, sources)
            : null;
        return null;
    }
}

/// <summary>
/// pip: <c>uploaded-prior-to</c> as a length of time ("P7D") under <c>[global]</c> in pip.ini:
/// the file named by <c>PIP_CONFIG_FILE</c>, the user's, the user's old location, the PC's.
/// The length form is understood from pip 26.1. Each Python has its own pip, so no single
/// version can be read.
/// </summary>
public sealed class PipCooldownCheck : CooldownCheck
{
    public const string Id = "sc.pip.cooldown";

    public PipCooldownCheck()
        : base(Id, "pip")
    {
    }

    private protected override ToolVersion MinimumVersion => new(26, 1, 0);

    private protected override string? Variable => "PIP_UPLOADED_PRIOR_TO";

    private protected override Cooldown Read(ConfigScalar value) => Durations.ParsePip(value.Text);

    private protected override CheckOutcome? Locate(SystemProbes probes, UserFolders folders, out ToolState? state)
    {
        state = null;
        IFileProbe files = probes.Files;

        if (PersistentEnvironment.Read(probes.Registry, "PIP_CONFIG_FILE", out string? configFile, out _) is { } failed)
        {
            return failed;
        }

        string[] paths =
        [
            .. configFile is null ? Array.Empty<string>() : [configFile],
            $@"{folders.Roaming}\pip\pip.ini",
            $@"{folders.Profile}\pip\pip.ini",
            $@"{folders.ProgramData}\pip\pip.ini",
        ];
        List<CooldownSource> sources = Existing(files, SettingsFormat.PythonIni, ["global", "uploaded-prior-to"], paths);

        // pip leaves its own folders behind once it has run: its cache, or its settings folder.
        // A Python merely being installed does not count: Pythons managed by uv never use pip.
        bool present = sources.Count > 0 ||
            SettingsFiles.FolderExists(files, $@"{folders.Local}\pip") ||
            SettingsFiles.FolderExists(files, $@"{folders.Roaming}\pip");
        if (present)
        {
            state = new ToolState(null, null, sources);
        }

        return null;
    }
}

/// <summary>Poetry: <c>min-release-age</c>, in days, under <c>[solver]</c> in the user's config.toml. From Poetry 2.4.</summary>
public sealed class PoetryCooldownCheck : CooldownCheck
{
    public const string Id = "sc.poetry.cooldown";

    public PoetryCooldownCheck()
        : base(Id, "Poetry")
    {
    }

    private protected override ToolVersion MinimumVersion => new(2, 4, 0);

    private protected override Cooldown Read(ConfigScalar value) => value.AsNumber is { } days
        ? Durations.FromNumber(days, TimeSpan.FromDays(1))
        : Cooldown.Invalid;

    private protected override CheckOutcome? Locate(SystemProbes probes, UserFolders folders, out ToolState? state)
    {
        string folder = $@"{folders.Roaming}\pypoetry";
        List<CooldownSource> sources = Existing(probes.Files, SettingsFormat.Toml, ["solver", "min-release-age"], $@"{folder}\config.toml");
        state = sources.Count > 0 || SettingsFiles.FolderExists(probes.Files, folder) ? new ToolState(null, null, sources) : null;
        return null;
    }
}

/// <summary>PDM: <c>exclude-newer</c>, written like "7d", under <c>[strategy]</c> in the user's config.toml. From PDM 2.27.</summary>
public sealed class PdmCooldownCheck : CooldownCheck
{
    public const string Id = "sc.pdm.cooldown";

    public PdmCooldownCheck()
        : base(Id, "PDM")
    {
    }

    private protected override ToolVersion MinimumVersion => new(2, 27, 0);

    private protected override Cooldown Read(ConfigScalar value)
    {
        Cooldown shortForm = Durations.ParseShort(value.Text, bareNumberUnit: null);

        // A date is a valid value too; it is recognised so that it can be called what it is.
        return shortForm.Kind != CooldownKind.Invalid ? shortForm : Durations.ParsePip(value.Text);
    }

    private protected override CheckOutcome? Locate(SystemProbes probes, UserFolders folders, out ToolState? state)
    {
        string folder = $@"{folders.Local}\pdm";
        List<CooldownSource> sources = Existing(probes.Files, SettingsFormat.Toml, ["strategy", "exclude-newer"], $@"{folder}\pdm\config.toml");
        state = sources.Count > 0 || SettingsFiles.FolderExists(probes.Files, folder) ? new ToolState(null, null, sources) : null;
        return null;
    }
}
