using SecReview.Checks;
using SecReview.Checks.BuiltIn.Programs;
using SecReview.Probing;
using SecReview.Tests.Fakes;
using static SecReview.Tests.Checks.Programs.ProgramChecksFixture;

namespace SecReview.Tests.Checks.Programs;

[TestClass]
public sealed class SoftwareKeysCheckTests
{
    private const string Product = @"SOFTWARE\Example\Product";
    private const string Product32 = @"SOFTWARE\WOW6432Node\Example\Product";

    private static readonly SoftwareKeysCheck Check = new();

    /// <summary>A PC with one product's settings, for 64-bit and 32-bit programs.</summary>
    private static FakeProbes Usual() => Pc()
        .WithRegistryKey(RegistryRoot.LocalMachine, Product)
        .WithRegistryKey(RegistryRoot.LocalMachine, Product + @"\Deeper\Still")
        .WithRegistryKey(RegistryRoot.LocalMachine, Product32)
        .WithRegistryKey(RegistryRoot.LocalMachine, @"SOFTWARE\Classes\Example.Document");

    [TestMethod]
    public void KeysOnlyAdministratorsCanChange_Pass()
    {
        CheckOutcome outcome = Check.Run(Usual());

        Assert.AreEqual(CheckStatus.Pass, outcome.Status, outcome.Summary);
        StringAssert.EndsWith(outcome.Summary, "settings keys are protected from change by standard users.");
    }

    [TestMethod]
    [DataRow(Product)]
    [DataRow(Product32)]
    [DataRow(@"SOFTWARE\Policies")]
    public void AProductsKeyStandardUsersCanChange_Fails(string key)
    {
        CheckOutcome outcome = Check.Run(Usual().WithKeyAccess(RegistryRoot.LocalMachine, key, FakeAccess.UsersAdd));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual($@"1 settings key is not protected from change: HKLM\{key}.", outcome.Summary);
        Assert.AreEqual("Users can change it", outcome.Findings[0].Found);
        Assert.AreEqual($@"HKLM\{key}", outcome.Findings[0].Source);
    }

    [TestMethod]
    public void AMakersKeyThatIsOpen_IsOneRow_WhateverIsInsideIt()
    {
        FakeProbes probes = Usual().WithKeyAccessBelow(RegistryRoot.LocalMachine, @"SOFTWARE\Example", FakeAccess.Protected.Allow(FakeAccess.AuthenticatedUsers, FakeAccess.Level.Modify));

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(@"1 settings key is not protected from change: HKLM\SOFTWARE\Example.", outcome.Summary);
        Assert.AreEqual("Authenticated Users can change it", outcome.Findings[0].Found);
    }

    [TestMethod]
    public void KeysUnderMicrosoftsOwnKey_AreCounted_NotJudged()
    {
        FakeProbes probes = Usual().WithKeyAccess(RegistryRoot.LocalMachine, @"SOFTWARE\Microsoft\Example Tracing", FakeAccess.UsersAdd);

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Pass, outcome.Status, outcome.Summary);
        CollectionAssert.Contains(
            outcome.Rows(), "Part of Windows: 1 key under Microsoft's own key can be changed by standard users; not judged [note]");
    }

    [TestMethod]
    public void OnlyAProductsKeyAndTheKeysDirectlyInsideIt_AreLookedAt()
    {
        FakeProbes probes = Usual()
            .WithKeyAccess(RegistryRoot.LocalMachine, Product + @"\Deeper", FakeAccess.UsersAdd)
            .WithKeyAccess(RegistryRoot.LocalMachine, @"SOFTWARE\Classes\Example.Document", FakeAccess.UsersAdd);

        Assert.AreEqual(CheckStatus.Pass, Check.Run(probes).Status, "deeper keys, and the registered components, are not this check's");
    }

    [TestMethod]
    public void AKeyOnlyAnAdministratorCanRead_IsNeedsAdministrator_ThenCouldNotCheckWhenElevated()
    {
        FakeProbes probes = Usual().WithKeyAccessFailure(RegistryRoot.LocalMachine, Product, ProbeFailure.AccessDenied());

        CheckOutcome ordinary = Check.Run(probes);
        CheckOutcome elevated = Check.Run(probes, elevated: true);

        Assert.AreEqual(CheckStatus.NeedsAdmin, ordinary.Status);
        StringAssert.EndsWith(ordinary.Summary, "1 more needs administrator rights to read.");
        Assert.AreEqual(CheckStatus.Error, elevated.Status);
    }

    [TestMethod]
    public void MoreKeysThanItReads_IsCouldNotCheck_NotAPartialAnswer()
    {
        FakeProbes probes = Usual();
        for (int number = 0; number <= SoftwareKeysCheck.MaximumKeys; number++)
        {
            probes.WithRegistryKey(RegistryRoot.LocalMachine, $@"SOFTWARE\Example\Product {number}");
        }

        // Run directly: the damaged copies of a PC this size are not worth their time.
        CheckOutcome outcome = Check.Run(new CheckContext(probes.Build(), TimeProvider.System, IsElevated: false, CancellationToken.None));

        Assert.AreEqual(CheckStatus.Error, outcome.Status);
        StringAssert.Contains(outcome.Summary, "More than 5000 settings keys");
    }

    [TestMethod]
    public void WhenTheRegistryCannotBeRead_TheAnswerIsCouldNotCheck_OrNeedsAdministrator()
    {
        FakeProbes failed = Usual();
        failed.RegistryFailure = ProbeFailure.Failed("The registry reported an error.");
        FakeProbes denied = Usual();
        denied.RegistryFailure = ProbeFailure.AccessDenied();

        Assert.AreEqual(CheckStatus.Error, Check.Run(failed).Status);
        Assert.AreEqual(CheckStatus.NeedsAdmin, Check.Run(denied).Status);
        Assert.AreEqual(CheckStatus.Error, Check.Run(new FakeProbes()).Status, "a PC without the key was not read right");
    }

    [TestMethod]
    public void ItReadsMostOfTheListAsANormalUser_AndKeepsAnAdministratorsAnswer()
    {
        Assert.AreEqual(SoftwareKeysCheck.Id, Check.Definition.Id);
        Assert.AreEqual(CheckCategory.Hardening, Check.Definition.Category);
        Assert.AreEqual(Severity.Low, Check.Definition.Severity);
        Assert.AreEqual(AdminNeed.ForFullDetail, Check.Definition.NeedsAdmin);
        Assert.IsTrue(Check.Definition.KeepsAdministratorAnswer);
    }
}
