using SecReview.Probing;

namespace SecReview.Checks.BuiltIn;

/// <summary>
/// Windows Firewall must be on, and blocking incoming connections by default, for the Domain,
/// Private and Public networks, since a laptop moves between them. A firewall from another
/// vendor that is registered with Windows and switched on also passes.
/// </summary>
public sealed class FirewallCheck : ICheck
{
    public const string Id = "firewall.enabled";

    private const string Expected = "On";
    private const string AllowsAll = "On, but allows all incoming connections";

    private static readonly FirewallProfiles[] Order =
        [FirewallProfiles.Domain, FirewallProfiles.Private, FirewallProfiles.Public];

    public CheckDefinition Definition { get; } = new(Id, CheckCategory.FirewallAndSharing, Severity.High);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        ProbeResult<FirewallState> state = context.Probes.Firewall.GetState();
        if (!state.IsOk)
        {
            return ProbeOutcomes.FromFailure(state, "the firewall state");
        }

        FirewallState firewall = state.Value!;
        var findings = new List<Finding>();
        var off = new List<string>();
        var open = new List<string>();
        foreach (FirewallProfiles profile in Order)
        {
            FirewallProfileState? settings = firewall.Profiles.FirstOrDefault(p => p.Profile == profile);
            if (settings is null)
            {
                return CheckOutcome.Error($"Windows did not report the {profile} network's firewall state.");
            }

            string item = (firewall.ActiveProfiles & profile) != 0
                ? $"{profile} network (in use)"
                : $"{profile} network";
            if (!settings.Enabled)
            {
                findings.Add(Finding.Problem(item, "Off", Expected));
                off.Add(profile.ToString());
            }
            else if (!settings.BlocksInboundByDefault)
            {
                // Switched on, yet every incoming connection is let through: on in name only.
                findings.Add(Finding.Problem(item, AllowsAll, Expected));
                open.Add(profile.ToString());
            }
            else
            {
                findings.Add(Finding.Ok(item, "On", Expected));
            }
        }

        if (off.Count == 0 && open.Count == 0)
        {
            return CheckOutcome.Pass("Windows Firewall is on for all networks.", findings);
        }

        // Another vendor's firewall may have taken over; Windows then switches its own off.
        string? other = ActiveFirewallFromAnotherVendor(context.Probes.SecurityCenter);
        if (other is not null)
        {
            var replaced = findings
                .Select(f => f.Status == FindingStatus.Problem ? Finding.Note(f.Item, "Replaced by another firewall") : f)
                .Append(Finding.Ok(other, "On", Expected))
                .ToList();
            return CheckOutcome.Pass($"{other} is protecting this PC.", replaced);
        }

        return off.Count > 0
            ? CheckOutcome.Fail($"Windows Firewall is off for {Networks(off)}.", findings)
            : CheckOutcome.Fail($"Windows Firewall allows all incoming connections on {Networks(open)}.", findings);
    }

    private static string? ActiveFirewallFromAnotherVendor(ISecurityCenterProbe securityCenter)
    {
        ProbeResult<IReadOnlyList<SecurityProduct>> products = securityCenter.GetProducts(SecurityProductKind.Firewall);
        if (!products.IsOk)
        {
            // Unknown is not "another firewall is on": the check stays a failure.
            return null;
        }

        // Windows lists its own firewall here too, and still as "on" when one network is off,
        // so only a product that is not part of Windows counts.
        return products.Value!.FirstOrDefault(p => p.State == SecurityProductState.On && !p.IsBuiltIn)?.Name;
    }

    private static string Networks(List<string> profiles) => profiles.Count == Order.Length
        ? "all networks"
        : $"the {Wording.JoinWithAnd(profiles)} network{Wording.Plural(profiles.Count)}";
}
