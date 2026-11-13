using SecReview.Checks;
using SecReview.Checks.BuiltIn.Programs;
using SecReview.Probing;
using SecReview.Tests.Fakes;
using static SecReview.Tests.Checks.Programs.ProgramChecksFixture;

namespace SecReview.Tests.Checks.Programs;

[TestClass]
public sealed class AllowedAppsCheckTests
{
    private const string Apps = AllowedAppsCheck.LocalKey + @"\" + AllowedAppsCheck.List;
    private const string PolicyApps = AllowedAppsCheck.PolicyKey + @"\" + AllowedAppsCheck.List;

    private static readonly AllowedAppsCheck Check = new();

    /// <summary>A PC with ransomware protection switched on and these apps allowed.</summary>
    private static FakeProbes On(params string[] apps)
    {
        FakeProbes probes = Pc().WithRegistryNumber(RegistryRoot.LocalMachine, AllowedAppsCheck.LocalKey, AllowedAppsCheck.Switch, 1);
        foreach (string app in apps)
        {
            probes.WithRegistryNumber(RegistryRoot.LocalMachine, Apps, app, 0);
        }

        return probes;
    }

    private static CheckOutcome Run(FakeProbes probes) => Check.Run(probes, elevated: true);

    [TestMethod]
    public void WithoutAdministratorRights_TheAnswerIsNeedsAdministrator_NotNone()
    {
        Assert.AreEqual(CheckStatus.NeedsAdmin, Check.Run(On(Loose)).Status);
        Assert.AreEqual(AdminNeed.Yes, Check.Definition.NeedsAdmin);
        Assert.AreEqual(AllowedAppsCheck.Id, Check.Definition.Id);
    }

    [TestMethod]
    public void WhileTheProtectionIsOff_ItDoesNotApply()
    {
        FakeProbes never = Pc().WithRegistryNumber(RegistryRoot.LocalMachine, Apps, Loose, 0);
        FakeProbes off = On(Loose).WithRegistryNumber(RegistryRoot.LocalMachine, AllowedAppsCheck.LocalKey, AllowedAppsCheck.Switch, 0);
        FakeProbes offByPolicy = On(Loose).WithRegistryNumber(RegistryRoot.LocalMachine, AllowedAppsCheck.PolicyKey, AllowedAppsCheck.Switch, 0);

        Assert.AreEqual(CheckStatus.NotApplicable, Run(never).Status);
        Assert.AreEqual(CheckStatus.NotApplicable, Run(off).Status);
        Assert.AreEqual(CheckStatus.NotApplicable, Run(offByPolicy).Status, "the organisation's setting decides");
    }

    [TestMethod]
    public void AllowedAppsOnlyAdministratorsCanChange_Pass()
    {
        CheckOutcome some = Run(On(Installed, @"%SystemRoot%\System32\cmd.exe"));
        CheckOutcome none = Run(On());

        Assert.AreEqual(CheckStatus.Pass, some.Status, some.Summary);
        Assert.AreEqual("All 2 allowed apps are protected from change by standard users.", some.Summary);
        Assert.AreEqual("Ransomware protection allows no extra apps.", none.Summary);
    }

    [TestMethod]
    public void AnAllowedAppStandardUsersCanReplace_Fails()
    {
        CheckOutcome outcome = Run(On(Installed, Loose));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("1 allowed app is not protected from change: Allowed app: agent.exe.", outcome.Summary);
        Assert.AreEqual($@"{Loose}: Authenticated Users can change C:\Tools", outcome.Findings[0].Found);
        Assert.AreEqual($@"HKLM\{Apps}", outcome.Findings[0].Source);
        Assert.IsFalse(outcome.ManagedByPolicy);
    }

    [TestMethod]
    public void AnAllowedAppThatIsGone_IsAProblemOnlyWhereAStandardUserCouldPutOneThere()
    {
        CheckOutcome leftBehind = Run(On(@"C:\Program Files\Gone\agent.exe"));
        CheckOutcome creatable = Run(On(@"C:\ProgramData\Gone\agent.exe"));

        Assert.AreEqual(CheckStatus.Pass, leftBehind.Status, leftBehind.Summary);
        Assert.AreEqual(CheckStatus.Fail, creatable.Status);
        Assert.AreEqual(@"C:\ProgramData\Gone\agent.exe is missing and Users can create it", creatable.Findings[0].Found);
    }

    [TestMethod]
    public void AnAppAllowedByTheOrganisationsPolicy_IsMarkedAsManaged()
    {
        FakeProbes probes = Pc()
            .WithRegistryNumber(RegistryRoot.LocalMachine, AllowedAppsCheck.PolicyKey, AllowedAppsCheck.Switch, 1)
            .WithRegistryNumber(RegistryRoot.LocalMachine, PolicyApps, Loose, 0);

        CheckOutcome outcome = Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.IsTrue(outcome.ManagedByPolicy);
    }

    [TestMethod]
    public void AnEntryThatCannotBeUnderstood_OrWhosePermissionsCannotBeRead_IsCouldNotCheck()
    {
        CheckOutcome odd = Run(On(@"relative\agent.exe"));
        CheckOutcome closed = Run(On(Installed).WithAccessFailure(@"C:\Program Files\Example", ProbeFailure.AccessDenied()));

        Assert.AreEqual(CheckStatus.Error, odd.Status);
        Assert.AreEqual(CheckStatus.Error, closed.Status, "already an administrator: asking again would change nothing");
    }

    [TestMethod]
    public void WhenWindowsRefusesTheList_TheAnswerIsNeedsAdministrator_OrCouldNotCheck()
    {
        FakeProbes denied = On(Installed);
        denied.RegistryFailure = ProbeFailure.AccessDenied();
        FakeProbes failed = On(Installed);
        failed.RegistryFailure = ProbeFailure.Failed("The registry reported an error.");

        Assert.AreEqual(CheckStatus.NeedsAdmin, Run(denied).Status);
        Assert.AreEqual(CheckStatus.Error, Run(failed).Status);
    }
}
