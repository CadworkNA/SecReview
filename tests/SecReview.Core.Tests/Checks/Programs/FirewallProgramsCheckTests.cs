using SecReview.Checks;
using SecReview.Checks.BuiltIn.Programs;
using SecReview.Probing;
using SecReview.Tests.Fakes;
using static SecReview.Tests.Checks.Programs.ProgramChecksFixture;

namespace SecReview.Tests.Checks.Programs;

[TestClass]
public sealed class FirewallProgramsCheckTests
{
    private static readonly FirewallProgramsCheck Check = new();

    /// <summary>A rule as Windows stores it: on, for connections coming in, allowing them, unless said otherwise.</summary>
    private static string Rule(string program, string name = "Example Agent", string action = "Allow", string direction = "In", string active = "TRUE", string more = "") =>
        $"v2.33|Action={action}|Active={active}|Dir={direction}|Protocol=6|{more}App={program}|Name={name}|Desc={Secret}|EmbedCtxt=Example|";

    private static FakeProbes With(params string[] rules)
    {
        FakeProbes probes = Pc();
        for (int index = 0; index < rules.Length; index++)
        {
            probes.WithText(FirewallProgramsCheck.LocalKey, $"{{00000000-0000-0000-0000-{index:D12}}}", rules[index]);
        }

        return probes;
    }

    [TestMethod]
    public void RulesForProtectedPrograms_Pass_AndRulesThatLetNothingInAreNotJudged()
    {
        FakeProbes probes = With(
            Rule(Installed),
            Rule(@"%SystemRoot%\System32\svchost.exe", name: "@FirewallAPI.dll,-28502"),
            Rule(Loose, action: "Block"),
            Rule(Loose, direction: "Out"),
            Rule(Loose, active: "FALSE"),
            "v2.33|Action=Allow|Active=TRUE|Dir=In|Name=Any program|",
            "v2.33|Action=Allow|Active=TRUE|Dir=In|App=System|Name=Windows itself|");

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Pass, outcome.Status, outcome.Summary);
        Assert.AreEqual("All 2 programs allowed through the firewall are protected from change by standard users.", outcome.Summary);
        Assert.IsFalse(outcome.Everything().Contains(Secret, StringComparison.Ordinal), "a rule's description is never shown");
    }

    [TestMethod]
    public void ARuleForAProgramStandardUsersCanChange_Fails_Once_HoweverManyRulesNameIt()
    {
        CheckOutcome outcome = Check.Run(With(Rule(Installed), Rule(Loose, "Loose Agent (TCP)"), Rule(Loose, "Loose Agent (UDP)")));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("1 program allowed through the firewall is not protected from change: Firewall rule: Loose Agent (TCP).", outcome.Summary);
        Assert.AreEqual($@"{Loose}: Authenticated Users can change C:\Tools", outcome.Findings[0].Found);
        Assert.AreEqual($@"HKLM\{FirewallProgramsCheck.LocalKey}", outcome.Findings[0].Source);
    }

    [TestMethod]
    public void ARuleWithoutANameOfItsOwn_IsNamedAfterItsProgram()
    {
        CheckOutcome outcome = Check.Run(With(Rule(Loose, name: "@{Example.Package_1.0.0.0_x64__abcdefgh?ms-resource://Example/Resources/Name}")));

        StringAssert.Contains(outcome.Summary, "Firewall rule for agent.exe");
    }

    [TestMethod]
    public void ARuleForAProgramOnTheNetwork_Fails_WithoutNamingTheServer()
    {
        CheckOutcome outcome = Check.Run(With(Rule(@"\\server\share\agent.exe")));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("On a network location", outcome.Findings[0].Found);
        Assert.IsFalse(outcome.Everything().Contains(@"\\server", StringComparison.OrdinalIgnoreCase));
    }

    [TestMethod]
    public void ARuleFromTheOrganisationsPolicy_IsMarkedAsManaged()
    {
        FakeProbes probes = With(Rule(Installed)).WithText(FirewallProgramsCheck.PolicyKey, "Example", Rule(Loose));

        Assert.IsTrue(Check.Run(probes).ManagedByPolicy);
        Assert.IsFalse(Check.Run(With(Rule(Loose))).ManagedByPolicy);
    }

    [TestMethod]
    public void ProgramsThatAreGone_OrEachUsersOwn_AreCounted_NotJudged()
    {
        FakeProbes probes = With(
            Rule(Installed, more: "LPort=8080|"),
            Rule(@"C:\Program Files\Gone\agent.exe"),
            Rule(@"%LOCALAPPDATA%\Example\agent.exe"),
            Rule(@"C:\Windows\System32\svchost.exe"));

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Pass, outcome.Status, outcome.Summary);
        string[] rows = outcome.Rows();
        CollectionAssert.Contains(rows, "Left behind: 1 allowed program is not there any more [note]");
        CollectionAssert.Contains(rows, "Each user's own: 1 allowed program is in the user's own folders; not judged [note]");
    }

    [TestMethod]
    public void AStoredRuleThatCannotBeUnderstood_IsCouldNotCheck_NotAPass()
    {
        FakeProbes probes = With(Rule(Installed), "not a rule at all")
            .WithRegistryNumber(RegistryRoot.LocalMachine, FirewallProgramsCheck.LocalKey, "A number", 3);

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Error, outcome.Status);
        StringAssert.StartsWith(outcome.Summary, "No problem in 1 program allowed through the firewall; 2 could not be judged.");
    }

    [TestMethod]
    public void NoRuleForAProgram_PassesWithItsOwnWords()
    {
        Assert.AreEqual("No firewall rule lets connections in for a program.", Check.Run(Pc()).Summary);
    }

    [TestMethod]
    public void WhenTheRulesCannotBeRead_TheAnswerIsCouldNotCheck_OrNeedsAdministrator()
    {
        FakeProbes failed = With(Rule(Installed));
        failed.RegistryFailure = ProbeFailure.Failed("The registry reported an error.");
        FakeProbes denied = With(Rule(Installed));
        denied.RegistryFailure = ProbeFailure.AccessDenied();

        Assert.AreEqual(CheckStatus.Error, Check.Run(failed).Status);
        Assert.AreEqual(CheckStatus.NeedsAdmin, Check.Run(denied).Status);
    }

    [TestMethod]
    public void PermissionsOnlyAnAdministratorCanRead_AreNeedsAdministrator_ThenCouldNotCheckWhenElevated()
    {
        FakeProbes probes = With(Rule(Installed)).WithAccessFailure(@"C:\Program Files\Example", ProbeFailure.AccessDenied());

        Assert.AreEqual(CheckStatus.NeedsAdmin, Check.Run(probes).Status);
        Assert.AreEqual(CheckStatus.Error, Check.Run(probes, elevated: true).Status);
    }

    [TestMethod]
    public void ItReadsMostOfTheListAsANormalUser_AndKeepsAnAdministratorsAnswer()
    {
        Assert.AreEqual(FirewallProgramsCheck.Id, Check.Definition.Id);
        Assert.AreEqual(CheckCategory.FirewallAndSharing, Check.Definition.Category);
        Assert.AreEqual(AdminNeed.ForFullDetail, Check.Definition.NeedsAdmin);
        Assert.IsTrue(Check.Definition.KeepsAdministratorAnswer);
    }

    [TestMethod]
    public void AStoredRule_IsReadFieldByField()
    {
        FirewallRuleText rule = FirewallRuleText.Parse(
            @"v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=8080|LPort=8081|App=C:\Program Files\Example\agent.exe|Name=Example Agent|Desc=a=b|")!;

        Assert.IsTrue(rule.Active);
        Assert.IsTrue(rule.Inbound);
        Assert.IsTrue(rule.Allows);
        Assert.AreEqual(@"C:\Program Files\Example\agent.exe", rule.Program);
        Assert.AreEqual("Example Agent", rule.Name);
    }

    [TestMethod]
    public void ARuleThatIsOffOrBlocks_AndOneForWindowsItself_AreToldApart()
    {
        FirewallRuleText rule = FirewallRuleText.Parse("V2.0|action=block|active=false|dir=out|App=System|Name=@FirewallAPI.dll,-1|")!;

        Assert.IsFalse(rule.Active);
        Assert.IsFalse(rule.Inbound);
        Assert.IsFalse(rule.Allows);
        Assert.IsNull(rule.Program, "Windows itself is not a file");
        Assert.IsNull(rule.Name, "a name kept elsewhere is not read");
    }

    [TestMethod]
    [DataRow(null)]
    [DataRow("")]
    [DataRow("v")]
    [DataRow("Action=Allow|Dir=In|")]
    [DataRow("v2.33|Name=No action or direction|")]
    [DataRow("version two|Action=Allow|Dir=In|")]
    public void TextThatIsNotARule_IsNotOne(string? text)
    {
        Assert.IsNull(FirewallRuleText.Parse(text));
    }

    [TestMethod]
    public void AnyText_IsReadWithoutFailing()
    {
        string[] pieces = ["v2.33", "|", "=", "Action", "Allow", "Dir", "In", "App", @"C:\", "LPort", "Name", "@", " ", "TRUE", "Active", "\t", "v", "2"];
        var random = new Random(20261112);
        for (int round = 0; round < 5000; round++)
        {
            string text = string.Concat(Enumerable.Range(0, random.Next(0, 20)).Select(_ => pieces[random.Next(pieces.Length)]));

            FirewallRuleText? rule = FirewallRuleText.Parse(text);

            _ = rule is null || (rule.Active | rule.Inbound | rule.Allows) || rule.Program is null || rule.Name is null;
        }

        Assert.IsNull(FirewallRuleText.Parse("v2|Action=Allow|Dir=In|" + new string('a', FirewallRuleText.MaximumLength)));
    }
}
