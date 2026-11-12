using SecReview.Checks;
using SecReview.SupplyChain.Cooldowns;
using SecReview.SupplyChain.Npm;
using SecReview.SupplyChain.Pnpm;
using SecReview.SupplyChain.Python;
using SecReview.SupplyChain.Scoop;
using SecReview.SupplyChain.Uv;
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
    ];
}
