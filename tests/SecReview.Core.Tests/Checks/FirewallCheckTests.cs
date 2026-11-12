using SecReview.Checks;
using SecReview.Checks.BuiltIn;
using SecReview.Probing;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.Checks;

[TestClass]
public sealed class FirewallCheckTests
{
    private static readonly FirewallCheck Check = new();

    private static FakeProbes With(
        bool domain, bool @private, bool @public, FirewallProfiles active = FirewallProfiles.Private, bool publicBlocksInbound = true) =>
        new()
        {
            Firewall = ProbeResult<FirewallState>.Ok(new FirewallState(
                [
                    new FirewallProfileState(FirewallProfiles.Domain, domain, BlocksInboundByDefault: true),
                    new FirewallProfileState(FirewallProfiles.Private, @private, BlocksInboundByDefault: true),
                    new FirewallProfileState(FirewallProfiles.Public, @public, publicBlocksInbound),
                ],
                active)),
            FirewallProducts = ProbeResult<IReadOnlyList<SecurityProduct>>.Ok([]),
        };

    private static SecurityProduct Firewall(string name, SecurityProductState state, bool builtIn) =>
        new(name, state, SignaturesUpToDate: null, IsBuiltIn: builtIn);

    [TestMethod]
    public void AllProfilesOn_Passes()
    {
        CheckOutcome outcome = Check.Run(With(true, true, true));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("Windows Firewall is on for all networks.", outcome.Summary);
        CollectionAssert.AreEqual(
            new[]
            {
                "Domain network: On (expected On) [ok]",
                "Private network (in use): On (expected On) [ok]",
                "Public network: On (expected On) [ok]",
            },
            outcome.Rows());
    }

    [TestMethod]
    public void PublicProfileOff_Fails_AndNamesIt_EvenWhenNotInUse()
    {
        CheckOutcome outcome = Check.Run(With(true, true, false));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("Windows Firewall is off for the Public network.", outcome.Summary);
        CollectionAssert.Contains(outcome.Rows(), "Public network: Off (expected On) [problem]");
        CollectionAssert.Contains(outcome.Rows(), "Private network (in use): On (expected On) [ok]");
    }

    [TestMethod]
    public void DomainProfileOff_Fails_UnlikeAToolThatOnlyLooksAtPrivateAndPublic()
    {
        CheckOutcome outcome = Check.Run(With(false, true, true));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("Windows Firewall is off for the Domain network.", outcome.Summary);
    }

    [TestMethod]
    public void TwoProfilesOff_NamesBoth()
    {
        CheckOutcome outcome = Check.Run(With(true, false, false));

        Assert.AreEqual("Windows Firewall is off for the Private and Public networks.", outcome.Summary);
    }

    [TestMethod]
    public void AllProfilesOff_SaysAllNetworks()
    {
        CheckOutcome outcome = Check.Run(With(false, false, false));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("Windows Firewall is off for all networks.", outcome.Summary);
    }

    [TestMethod]
    public void OnButAllowingAllIncomingConnections_Fails_BecauseItIsOnInNameOnly()
    {
        CheckOutcome outcome = Check.Run(With(true, true, true, publicBlocksInbound: false));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("Windows Firewall allows all incoming connections on the Public network.", outcome.Summary);
        CollectionAssert.Contains(
            outcome.Rows(), "Public network: On, but allows all incoming connections (expected On) [problem]");
    }

    [TestMethod]
    public void AProfileThatIsOff_IsReportedBeforeOneThatAllowsEverything()
    {
        CheckOutcome outcome = Check.Run(With(true, false, true, publicBlocksInbound: false));

        Assert.AreEqual("Windows Firewall is off for the Private network.", outcome.Summary);
        Assert.AreEqual(2, outcome.Findings.Count(f => f.Status == FindingStatus.Problem));
    }

    [TestMethod]
    public void WindowsFirewallOff_ButAnotherVendorsFirewallIsOn_Passes_AndNamesIt()
    {
        FakeProbes probes = With(false, false, false);
        probes.FirewallProducts = ProbeResult<IReadOnlyList<SecurityProduct>>.Ok(
            [Firewall("Example Firewall", SecurityProductState.On, builtIn: false)]);

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("Example Firewall is protecting this PC.", outcome.Summary);
        CollectionAssert.Contains(outcome.Rows(), "Example Firewall: On (expected On) [ok]");
        CollectionAssert.Contains(outcome.Rows(), "Public network: Replaced by another firewall [note]");
    }

    [TestMethod]
    public void WindowsFirewallOff_AndTheOtherFirewallIsNotOn_Fails()
    {
        FakeProbes probes = With(true, true, false);
        probes.FirewallProducts = ProbeResult<IReadOnlyList<SecurityProduct>>.Ok(
            [Firewall("Example Firewall", SecurityProductState.Snoozed, builtIn: false)]);

        Assert.AreEqual(CheckStatus.Fail, Check.Run(probes).Status);
    }

    [TestMethod]
    [DataRow("Windows Firewall", DisplayName = "English name")]
    [DataRow("Windows-Firewall", DisplayName = "German name")]
    [DataRow("Pare-feu Windows", DisplayName = "French name")]
    public void WindowsOwnFirewallListedAsOn_NeverCountsAsAnotherFirewall_WhateverItIsCalled(string name)
    {
        // Windows lists its own firewall as a product, still "on" when one network is off, and
        // under a translated name. It is recognised by being part of Windows, not by the name.
        FakeProbes probes = With(true, true, false);
        probes.FirewallProducts = ProbeResult<IReadOnlyList<SecurityProduct>>.Ok(
            [Firewall(name, SecurityProductState.On, builtIn: true)]);

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("Windows Firewall is off for the Public network.", outcome.Summary);
    }

    [TestMethod]
    public void WindowsFirewallOff_AndProductsCannotBeRead_Fails_NotPasses()
    {
        FakeProbes probes = With(true, true, false);
        probes.FirewallProducts = ProbeFailure.NotSupported("Windows Server has no Security Center.");

        Assert.AreEqual(CheckStatus.Fail, Check.Run(probes).Status);
    }

    [TestMethod]
    [DataRow(ProbeStatus.Failed, CheckStatus.Error)]
    [DataRow(ProbeStatus.AccessDenied, CheckStatus.NeedsAdmin)]
    [DataRow(ProbeStatus.NotSupported, CheckStatus.Error)]
    [DataRow(ProbeStatus.NotFound, CheckStatus.Error)]
    public void FirewallStateCannotBeRead_IsNeverAPassAFailOrDoesNotApply(ProbeStatus probeStatus, CheckStatus expected)
    {
        var probes = new FakeProbes { Firewall = FailureOf(probeStatus) };

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(expected, outcome.Status);
        Assert.IsFalse(string.IsNullOrWhiteSpace(outcome.Summary));
    }

    [TestMethod]
    public void AProfileMissingFromTheAnswer_IsCouldNotCheck()
    {
        var probes = new FakeProbes
        {
            Firewall = ProbeResult<FirewallState>.Ok(new FirewallState(
                [new FirewallProfileState(FirewallProfiles.Private, Enabled: true, BlocksInboundByDefault: true)],
                FirewallProfiles.Private)),
        };

        Assert.AreEqual(CheckStatus.Error, Check.Run(probes).Status);
    }

    internal static ProbeFailure FailureOf(ProbeStatus status) => status switch
    {
        ProbeStatus.AccessDenied => ProbeFailure.AccessDenied(),
        ProbeStatus.NotSupported => ProbeFailure.NotSupported("Not on this edition."),
        ProbeStatus.NotFound => ProbeFailure.NotFound(),
        _ => ProbeFailure.Failed("Reading failed (0x80004005)."),
    };
}
