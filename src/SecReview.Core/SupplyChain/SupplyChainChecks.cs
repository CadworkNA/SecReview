using SecReview.Checks;
using SecReview.Malware;
using SecReview.SupplyChain.Agents;
using SecReview.SupplyChain.Cargo;
using SecReview.SupplyChain.Cooldowns;
using SecReview.SupplyChain.Credentials;
using SecReview.SupplyChain.Editors;
using SecReview.SupplyChain.Git;
using SecReview.SupplyChain.Go;
using SecReview.SupplyChain.Npm;
using SecReview.SupplyChain.NuGet;
using SecReview.SupplyChain.Pnpm;
using SecReview.SupplyChain.Python;
using SecReview.SupplyChain.Scoop;
using SecReview.SupplyChain.Trust;
using SecReview.SupplyChain.Uv;
using SecReview.SupplyChain.Variables;
using SecReview.SupplyChain.WindowsPackages;
using SecReview.SupplyChain.Yarn;

namespace SecReview.SupplyChain;

/// <summary>
/// The developer supply-chain checks, in the order they are shown. Each one "does not apply"
/// when its tool is not installed, and none of them runs the tool it looks at: they read
/// settings files, the registry and persistent environment variables only.
/// </summary>
public static class SupplyChainChecks
{
    public static IReadOnlyList<ICheck> All { get; } =
    [
        new UvCooldownCheck(),
        new UvSourcesCheck(),
        new UvCredentialsCheck(),
        new PnpmCooldownCheck(),
        new PnpmSettingsCheck(),
        new PnpmCredentialsCheck(),
        new ScoopBucketsCheck(),
        new ScoopAppsCheck(),
        new ScoopUpdatesCheck(),
        new ScoopCredentialsCheck(),
        new NpmCooldownCheck(),
        new YarnCooldownCheck(),
        new BunCooldownCheck(),
        new PipCooldownCheck(),
        new PoetryCooldownCheck(),
        new PdmCooldownCheck(),
        new NpmSettingsCheck(),
        new NpmCredentialsCheck(),
        new YarnSettingsCheck(),
        new YarnCredentialsCheck(),
        new PipSettingsCheck(),
        new PythonCredentialsCheck(),
        new NuGetSourcesCheck(),
        new NuGetCredentialsCheck(),
        new NuGetCooldownCheck(),
        new CargoSettingsCheck(),
        new CargoCredentialsCheck(),
        new GoSettingsCheck(),
        new EditorUpdatesCheck(),
        new EditorSettingsCheck(),
        new McpServersCheck(),
        new AgentPermissionsCheck(),
        new GitSettingsCheck(),
        new GitCredentialsCheck(),
        new GitHubCliCredentialsCheck(),
        new DockerSettingsCheck(),
        new DockerCredentialsCheck(),
        new CloudCredentialsCheck(),
        new BuildCredentialsCheck(),
        new WingetPoliciesCheck(),
        new ChocolateySettingsCheck(),
        new EnvironmentTlsCheck(),
        new EnvironmentInjectionCheck(),
        new EnvironmentTokensCheck(),
        new RootCertificatesCheck(),
        new DefenderExclusionsCheck(),
        new InstalledMalwareCheck(),
        new DownloadedMalwareCheck(),
        new MalwareListCheck(),
    ];
}
