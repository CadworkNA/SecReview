using SecReview.Checks;
using SecReview.SupplyChain.Pnpm;
using SecReview.SupplyChain.Uv;

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
    ];
}
