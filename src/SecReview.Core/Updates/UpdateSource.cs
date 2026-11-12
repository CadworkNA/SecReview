using System.Reflection;
using SecReview.Malware;
using SecReview.Probing;

namespace SecReview.Updates;

/// <summary>
/// Where this build looks for updates: one address, compiled in by the release workflow
/// (<c>build.ps1 -UpdateUrl</c>). A build without one (a developer's, a fork's) never looks,
/// and never installs anything. The address is not a setting: nothing on the PC can point
/// SecReview at another one.
/// </summary>
public sealed class UpdateSource
{
    /// <summary>The key of the assembly metadata that holds the address.</summary>
    public const string MetadataKey = "UpdateManifestUrl";

    /// <summary>Where GitHub serves the files of a release from, after github.com itself.</summary>
    private static readonly string[] GitHubDownloadHosts = ["objects.githubusercontent.com", "release-assets.githubusercontent.com"];

    private readonly HashSet<string> _hosts = new(StringComparer.OrdinalIgnoreCase);

    /// <param name="manifestUrl">The address of <c>latest.json</c>; null or empty for a build that does not update.</param>
    public UpdateSource(string? manifestUrl)
    {
        if (!string.IsNullOrWhiteSpace(manifestUrl) && Uri.TryCreate(manifestUrl, UriKind.Absolute, out Uri? url) && IsPlainHttps(url))
        {
            ManifestUrl = url;
            _hosts.Add(url.Host);
            if (url.Host.Equals("github.com", StringComparison.OrdinalIgnoreCase))
            {
                _hosts.UnionWith(GitHubDownloadHosts);
            }
        }
    }

    /// <summary>The source compiled into this build.</summary>
    public static UpdateSource Compiled { get; } = new(
        typeof(UpdateSource).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .FirstOrDefault(attribute => attribute.Key == MetadataKey)?.Value);

    /// <summary>The address of <c>latest.json</c>; null when this build does not look for updates.</summary>
    public Uri? ManifestUrl { get; }

    /// <summary>Whether this build looks for updates at all.</summary>
    public bool IsConfigured => ManifestUrl is not null;

    /// <summary>
    /// Whether SecReview may fetch from an address: HTTPS, on the manifest's own host (or, for
    /// a manifest on GitHub, where GitHub serves release files from), with no user name,
    /// password or unusual port in it. Applied to the manifest, to the setup program, and to
    /// every address a server sends SecReview on to.
    /// </summary>
    public bool Allows(Uri url)
    {
        ArgumentNullException.ThrowIfNull(url);
        return IsPlainHttps(url) && _hosts.Contains(url.Host);
    }

    private static bool IsPlainHttps(Uri url) =>
        url.IsAbsoluteUri && url.Scheme == Uri.UriSchemeHttps && url.IsDefaultPort && url.UserInfo.Length == 0 && url.Host.Length > 0;
}

/// <summary>What the organisation has decided about updates (<c>HKLM\Software\Policies\SecReview</c>).</summary>
/// <param name="NoUpdateCheck">SecReview does not look for updates.</param>
/// <param name="NoSelfUpdate">SecReview says when there is an update but does not install it.</param>
public readonly record struct UpdatePolicy(bool NoUpdateCheck, bool NoSelfUpdate)
{
    public const string Key = @"SOFTWARE\Policies\SecReview";
    public const string NoUpdateCheckValue = "NoUpdateCheck";
    public const string NoSelfUpdateValue = "NoSelfUpdate";

    /// <summary>
    /// Reads the policy. A value that cannot be read counts as set: an organisation that said
    /// no must not be overruled by a failed read.
    /// </summary>
    public static UpdatePolicy Read(IRegistryProbe registry)
    {
        ArgumentNullException.ThrowIfNull(registry);
        return new UpdatePolicy(IsSet(registry, NoUpdateCheckValue), IsSet(registry, NoSelfUpdateValue));
    }

    private static bool IsSet(IRegistryProbe registry, string name)
    {
        ProbeResult<RegistryValue> value = registry.GetValue(RegistryRoot.LocalMachine, Key, name);
        return value.IsOk ? value.Value is not { Type: RegistryValueType.Number, Number: 0 } : value.Status != ProbeStatus.NotFound;
    }
}

/// <summary>The rules of updating that need no network and no Windows.</summary>
public static class UpdateRules
{
    /// <summary>SecReview looks for updates this often.</summary>
    public static readonly TimeSpan CheckInterval = TimeSpan.FromHours(24);

    /// <summary>A failed look is tried again after this long, not a day later.</summary>
    public static readonly TimeSpan RetryInterval = TimeSpan.FromHours(2);

    /// <summary>
    /// Whether an offered version is an update for the installed one: a higher version.
    /// A pre-release is only offered to someone who runs a pre-release. False when either is
    /// not a version: nothing is installed on a guess.
    /// </summary>
    public static bool IsNewer(string offered, string installed)
    {
        ArgumentNullException.ThrowIfNull(offered);
        ArgumentNullException.ThrowIfNull(installed);

        if (PackageVersions.Compare(PackageEcosystem.Npm, offered, installed) is not > 0)
        {
            return false;
        }

        return !IsPreRelease(offered) || IsPreRelease(installed);
    }

    public static bool IsPreRelease(string version) => version.Contains('-', StringComparison.Ordinal);

    /// <summary>
    /// Whether it is time to look again: never looked, the interval is over, or the last look
    /// is dated after now (the clock was changed). Each PC looks at its own time of day
    /// (<paramref name="spread"/>, a fraction of an hour that differs per PC), so that all
    /// PCs do not ask at once.
    /// </summary>
    public static bool IsCheckDue(UpdateState state, DateTimeOffset now, double spread = 0)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (state.CheckedAt is not { } last || last > now)
        {
            return true;
        }

        TimeSpan wait = state.Outcome == UpdateOutcome.Failed ? RetryInterval : CheckInterval + TimeSpan.FromHours(Math.Clamp(spread, 0, 1));
        return now - last >= wait;
    }
}
