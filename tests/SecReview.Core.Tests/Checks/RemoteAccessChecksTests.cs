using SecReview.Checks;
using SecReview.Checks.BuiltIn;
using SecReview.Probing;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.Checks;

[TestClass]
public sealed class RemoteAccessChecksTests
{
    // Remote Desktop

    private static FakeProbes Rdp(long? deny, long? nla = null, long? policyDeny = null, long? policyNla = null)
    {
        var probes = new FakeProbes();
        Set(RemoteDesktopCheck.LocalKey, RemoteDesktopCheck.DenyValue, deny);
        Set(RemoteDesktopCheck.ListenerKey, RemoteDesktopCheck.NlaValue, nla);
        Set(RemoteDesktopCheck.PolicyKey, RemoteDesktopCheck.DenyValue, policyDeny);
        Set(RemoteDesktopCheck.PolicyKey, RemoteDesktopCheck.NlaValue, policyNla);
        return probes;

        void Set(string key, string name, long? value)
        {
            if (value is not null)
            {
                probes.WithRegistryNumber(RegistryRoot.LocalMachine, key, name, value.Value);
            }
        }
    }

    [TestMethod]
    public void Rdp_Off_Passes()
    {
        CheckOutcome outcome = new RemoteDesktopCheck().Run(Rdp(deny: 1));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("Remote Desktop is off.", outcome.Summary);
        Assert.IsFalse(outcome.ManagedByPolicy);
    }

    [TestMethod]
    public void Rdp_NothingSet_IsTheWindowsDefault_Off()
    {
        CheckOutcome outcome = new RemoteDesktopCheck().Run(Rdp(deny: null));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("Off (Windows default)", outcome.Findings[0].Found);
    }

    [TestMethod]
    public void Rdp_OnWithNetworkLevelAuthentication_Passes_AndSaysItIsOn()
    {
        CheckOutcome outcome = new RemoteDesktopCheck().Run(Rdp(deny: 0, nla: 1));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        CollectionAssert.AreEqual(
            new[] { "Remote Desktop: On [note]", "Network Level Authentication: Required (expected Required) [ok]" },
            outcome.Rows());
    }

    [TestMethod]
    public void Rdp_OnWithoutNetworkLevelAuthentication_Fails()
    {
        CheckOutcome outcome = new RemoteDesktopCheck().Run(Rdp(deny: 0, nla: 0));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("Remote Desktop is on without Network Level Authentication.", outcome.Summary);
    }

    [TestMethod]
    public void Rdp_On_ButTheAuthenticationSettingIsMissing_IsCouldNotCheck()
    {
        Assert.AreEqual(CheckStatus.Error, new RemoteDesktopCheck().Run(Rdp(deny: 0)).Status);
    }

    [TestMethod]
    public void Rdp_APolicyWinsOverTheLocalSetting_AndIsMarked()
    {
        CheckOutcome turnedOn = new RemoteDesktopCheck().Run(Rdp(deny: 1, nla: 1, policyDeny: 0));
        Assert.AreEqual(CheckStatus.Pass, turnedOn.Status);
        Assert.AreEqual("Remote Desktop is on and requires Network Level Authentication.", turnedOn.Summary);
        Assert.IsTrue(turnedOn.ManagedByPolicy);

        CheckOutcome turnedOff = new RemoteDesktopCheck().Run(Rdp(deny: 0, nla: 0, policyDeny: 1));
        Assert.AreEqual(CheckStatus.Pass, turnedOff.Status);
        Assert.IsTrue(turnedOff.ManagedByPolicy);

        CheckOutcome weakened = new RemoteDesktopCheck().Run(Rdp(deny: 0, nla: 1, policyNla: 0));
        Assert.AreEqual(CheckStatus.Fail, weakened.Status);
        Assert.IsTrue(weakened.ManagedByPolicy);
    }

    [TestMethod]
    public void Rdp_Unreadable_IsNeverAPass()
    {
        var probes = new FakeProbes { RegistryFailure = ProbeFailure.Failed("Reading the registry failed.") };

        Assert.AreEqual(CheckStatus.Error, new RemoteDesktopCheck().Run(probes).Status);
    }

    // Remote management services

    [TestMethod]
    public void Services_NotInstalled_Passes()
    {
        CheckOutcome outcome = new RemoteServicesCheck().Run(new FakeProbes());

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.IsTrue(outcome.Findings.All(f => f.Found == "Not installed"));
    }

    [TestMethod]
    public void Services_InstalledButStopped_Passes()
    {
        FakeProbes probes = new FakeProbes()
            .WithService("WinRM", ServiceStartType.Manual, isRunning: false)
            .WithService("sshd", ServiceStartType.Disabled, isRunning: false);

        Assert.AreEqual(CheckStatus.Pass, new RemoteServicesCheck().Run(probes).Status);
    }

    [TestMethod]
    public void Services_Running_Fail_AndAreNamed()
    {
        FakeProbes one = new FakeProbes().WithService("sshd", ServiceStartType.Automatic, isRunning: true);
        Assert.AreEqual("OpenSSH server is running.", new RemoteServicesCheck().Run(one).Summary);

        FakeProbes both = one.WithService("WinRM", ServiceStartType.Automatic, isRunning: true);
        CheckOutcome outcome = new RemoteServicesCheck().Run(both);
        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("Windows Remote Management and OpenSSH server are running.", outcome.Summary);
    }

    [TestMethod]
    public void Services_Unreadable_IsCouldNotCheck()
    {
        FakeProbes probes = new FakeProbes().WithServiceFailure("WinRM", ProbeFailure.Failed("Asking the service manager failed."));

        Assert.AreEqual(CheckStatus.Error, new RemoteServicesCheck().Run(probes).Status);
    }

    // Shared folders

    private static FakeProbes Shares(params (string Name, long? Type)[] shares) => new FakeProbes().WithWmiObjects(
        SharedFoldersCheck.WmiNamespace,
        SharedFoldersCheck.WmiClass,
        [.. shares.Select(s => FakeProbes.Wmi(("Name", s.Name), ("Type", s.Type)))]);

    [TestMethod]
    public void Shares_OnlyWindowsOwn_Pass()
    {
        // Administrative disk share, administrative IPC share, printer drivers, a shared printer.
        FakeProbes probes = Shares(("C$", 2147483648), ("IPC$", 2147483651), ("print$", 0), ("Printer", 1));

        Assert.AreEqual(CheckStatus.Pass, new SharedFoldersCheck().Run(probes).Status);
        Assert.AreEqual(CheckStatus.Pass, new SharedFoldersCheck().Run(Shares()).Status);
    }

    [TestMethod]
    public void Shares_AFolder_Fails_WithTheCountOnly()
    {
        CheckOutcome outcome = new SharedFoldersCheck().Run(Shares(("C$", 2147483648), ("Private project", 0), ("Scans", 0)));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("2 folders are shared on the network.", outcome.Summary);
        Assert.IsFalse(outcome.Findings.Any(f => (f.Item + f.Found).Contains("Private project", StringComparison.Ordinal)), "share names stay out");
    }

    [TestMethod]
    public void Shares_OfUnknownKind_OrUnreadable_AreCouldNotCheck()
    {
        Assert.AreEqual(CheckStatus.Error, new SharedFoldersCheck().Run(Shares(("Something", null))).Status);
        Assert.AreEqual(CheckStatus.Error, new SharedFoldersCheck().Run(new FakeProbes()).Status);
    }

    // Built-in accounts

    private static FakeProbes Accounts(bool? administratorDisabled, bool? guestDisabled, bool local = true)
    {
        var accounts = new List<WmiObject>
        {
            FakeProbes.Wmi(("SID", "S-1-5-21-1111-2222-3333-1001"), ("Disabled", false), ("LocalAccount", true)),
        };
        if (administratorDisabled is not null)
        {
            accounts.Add(FakeProbes.Wmi(("SID", "S-1-5-21-1111-2222-3333-500"), ("Disabled", administratorDisabled), ("LocalAccount", local)));
        }

        if (guestDisabled is not null)
        {
            accounts.Add(FakeProbes.Wmi(("SID", "S-1-5-21-1111-2222-3333-501"), ("Disabled", guestDisabled), ("LocalAccount", local)));
        }

        return new FakeProbes().WithWmiObjects(BuiltInAccountsCheck.WmiNamespace, BuiltInAccountsCheck.WmiClass, [.. accounts]);
    }

    [TestMethod]
    [DataRow(true, true, CheckStatus.Pass, "The built-in Administrator and Guest accounts are disabled.")]
    [DataRow(false, true, CheckStatus.Fail, "The built-in Administrator account is enabled.")]
    [DataRow(true, false, CheckStatus.Fail, "The Guest account is enabled.")]
    [DataRow(false, false, CheckStatus.Fail, "The built-in Administrator and Guest accounts are enabled.")]
    public void Accounts_FollowWhetherTheyAreDisabled(bool administrator, bool guest, CheckStatus expected, string summary)
    {
        CheckOutcome outcome = new BuiltInAccountsCheck().Run(Accounts(administrator, guest));

        Assert.AreEqual(expected, outcome.Status);
        Assert.AreEqual(summary, outcome.Summary);
        Assert.AreEqual(2, outcome.Findings.Count, "other accounts are not listed");
    }

    [TestMethod]
    public void Accounts_AnOrdinaryAccountWhoseNumberEndsIn500_IsNotTheAdministrator()
    {
        FakeProbes probes = new FakeProbes().WithWmiObjects(
            BuiltInAccountsCheck.WmiNamespace,
            BuiltInAccountsCheck.WmiClass,
            FakeProbes.Wmi(("SID", "S-1-5-21-1111-2222-3333-1500"), ("Disabled", false), ("LocalAccount", true)),
            FakeProbes.Wmi(("SID", "S-1-5-21-1111-2222-3333-500"), ("Disabled", true), ("LocalAccount", true)),
            FakeProbes.Wmi(("SID", "S-1-5-21-1111-2222-3333-501"), ("Disabled", true), ("LocalAccount", true)));

        Assert.AreEqual(CheckStatus.Pass, new BuiltInAccountsCheck().Run(probes).Status);
    }

    [TestMethod]
    public void Accounts_NotListed_OrOnlyDomainOnes_AreCouldNotCheck()
    {
        Assert.AreEqual(CheckStatus.Error, new BuiltInAccountsCheck().Run(Accounts(null, true)).Status);
        Assert.AreEqual(CheckStatus.Error, new BuiltInAccountsCheck().Run(Accounts(true, null)).Status);
        Assert.AreEqual(CheckStatus.Error, new BuiltInAccountsCheck().Run(Accounts(false, false, local: false)).Status, "only local accounts are asked for");
        Assert.AreEqual(CheckStatus.Error, new BuiltInAccountsCheck().Run(new FakeProbes()).Status);
    }
}
