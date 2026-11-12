using SecReview.Checks;
using SecReview.Checks.BuiltIn.Ssh;
using SecReview.Probing;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.Checks.Ssh;

[TestClass]
public sealed class SshConfigCheckTests
{
    private const string SystemFile = @"C:\ProgramData\ssh\ssh_config";

    private static readonly SshConfigCheck Check = new();

    private static FakeProbes Config(string text) => new FakeProbes().WithFile(SshFixtures.Path("config"), text);

    [TestMethod]
    public void NoSettingsFile_DoesNotApply()
    {
        Assert.AreEqual(CheckStatus.NotApplicable, Check.Run(new FakeProbes()).Status);
    }

    [TestMethod]
    public void AnOrdinaryFile_Passes()
    {
        CheckOutcome outcome = Check.Run(Config("# my hosts\nHost build\n  HostName build.example\n  User dev\n"));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        CollectionAssert.AreEqual(
            new[]
            {
                "Agent forwarding for every host: Off (expected Off) [ok]",
                "Host key checking for every host: On (expected On) [ok]",
            },
            outcome.Rows());
    }

    [TestMethod]
    [DataRow("ForwardAgent yes\n")]
    [DataRow("forwardagent=yes\n")]
    [DataRow("Host *\n  ForwardAgent \"yes\"\n")]
    [DataRow("Host * !bastion\n\tForwardAgent yes\n")]
    [DataRow("Match all\n  ForwardAgent yes\n")]
    [DataRow("Match final all\n  ForwardAgent yes\n")]
    [DataRow("ForwardAgent $SSH_AUTH_SOCK\n")]
    [DataRow("ForwardAgent true\n")]
    [DataRow("Host one\n  User a\nHost *\n  ForwardAgent yes # comment\n")]
    public void AgentForwardingForEveryHost_Fails(string text)
    {
        CheckOutcome outcome = Check.Run(Config(text));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("SSH forwards your agent to every host.", outcome.Summary);
        Assert.AreEqual(FindingStatus.Problem, outcome.Findings[0].Status);
    }

    [TestMethod]
    public void AgentForwardingForOneNamedHost_IsOnlyListed()
    {
        CheckOutcome outcome = Check.Run(Config("Host bastion\n  ForwardAgent yes\n"));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("Agent forwarding for \"Host bastion\": On [note]", outcome.Rows()[2]);
        Assert.AreEqual("config, line 2", outcome.Findings[2].Source);
    }

    [TestMethod]
    public void TheFirstValueWins_AsInOpenSsh()
    {
        // The setting for every host comes first, so the later one for "bastion" never applies.
        CheckOutcome off = Check.Run(Config("ForwardAgent no\nHost bastion\n  ForwardAgent yes\n"));
        Assert.AreEqual(CheckStatus.Pass, off.Status);
        Assert.AreEqual(2, off.Findings.Count);

        // "no" for every host first: a later "yes" for every host is not used either.
        Assert.AreEqual(CheckStatus.Pass, Check.Run(Config("Host *\n  ForwardAgent no\nHost *\n  ForwardAgent yes\n")).Status);
        Assert.AreEqual(CheckStatus.Fail, Check.Run(Config("Host *\n  ForwardAgent yes\nHost *\n  ForwardAgent no\n")).Status);
    }

    [TestMethod]
    [DataRow("StrictHostKeyChecking no\n")]
    [DataRow("Host *\n  StrictHostKeyChecking off\n")]
    [DataRow("StrictHostKeyChecking false\n")]
    [DataRow("StrictHostKeyChecking FALSE\n")]
    public void HostKeyCheckingOffForEveryHost_Fails(string text)
    {
        CheckOutcome outcome = Check.Run(Config(text));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("SSH does not check host keys.", outcome.Summary);
    }

    [TestMethod]
    [DataRow("yes")]
    [DataRow("ask")]
    [DataRow("accept-new")]
    [DataRow("true")]
    public void OtherHostKeyCheckingValues_Pass(string value)
    {
        Assert.AreEqual(CheckStatus.Pass, Check.Run(Config($"StrictHostKeyChecking {value}\n")).Status);
    }

    [TestMethod]
    [DataRow("no")]
    [DataRow("false")]
    [DataRow("False")]
    public void AgentForwardingSwitchedOff_InEitherSpelling_Passes(string value)
    {
        Assert.AreEqual(CheckStatus.Pass, Check.Run(Config($"Host *\n  ForwardAgent {value}\n")).Status);
    }

    [TestMethod]
    public void HostKeyCheckingOffForOneNamedHost_IsOnlyListed()
    {
        CheckOutcome outcome = Check.Run(Config("Host localhost 127.0.0.1\n  StrictHostKeyChecking no\n  UserKnownHostsFile /dev/null\n"));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("Host key checking for \"Host localhost 127.0.0.1\": Off [note]", outcome.Rows()[2]);
    }

    [TestMethod]
    public void KnownHostsThrownAwayForEveryHost_Fails()
    {
        CheckOutcome outcome = Check.Run(Config("UserKnownHostsFile /dev/null\nForwardAgent yes\n"));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("SSH forwards your agent to every host and does not remember known hosts.", outcome.Summary);
    }

    [TestMethod]
    public void TheSystemWideFile_IsReadAfterTheUsersOwn()
    {
        FakeProbes systemOnly = new FakeProbes().WithFile(SystemFile, "ForwardAgent yes\n");
        Assert.AreEqual(CheckStatus.Fail, Check.Run(systemOnly).Status);
        Assert.AreEqual("ssh_config, line 1", Check.Run(systemOnly).Findings[0].Source);

        FakeProbes userFirst = Config("ForwardAgent no\n").WithFile(SystemFile, "ForwardAgent yes\n");
        Assert.AreEqual(CheckStatus.Pass, Check.Run(userFirst).Status);
    }

    [TestMethod]
    public void IncludedFiles_AreRead_WhereTheyAreIncluded()
    {
        FakeProbes probes = Config("Include extra.conf\nForwardAgent no\n")
            .WithFile(SshFixtures.Path("extra.conf"), "ForwardAgent yes\n");

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("extra.conf, line 1", outcome.Findings[0].Source);
    }

    [TestMethod]
    public void IncludedFiles_ByWildcard_AndFromTheUserFolder()
    {
        FakeProbes probes = Config("Include conf.d/*.conf ~/.ssh/more\n")
            .WithFile(SshFixtures.Path(@"conf.d\a.conf"), "Host a\n  User x\n")
            .WithFile(SshFixtures.Path(@"conf.d\b.conf"), "Host *\n  StrictHostKeyChecking no\n")
            .WithFile(SshFixtures.Path(@"conf.d\ignored.txt"), "ForwardAgent yes\n")
            .WithFile(SshFixtures.Path("more"), "ForwardAgent no\n");

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("SSH does not check host keys.", outcome.Summary);
    }

    [TestMethod]
    public void AnIncludeInsideAHostBlock_AppliesToThatHostOnly()
    {
        FakeProbes probes = Config("Host bastion\n  Include extra.conf\n")
            .WithFile(SshFixtures.Path("extra.conf"), "ForwardAgent yes\nHost *\n  StrictHostKeyChecking no\n");

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual(4, outcome.Findings.Count, "both are listed as notes for that host");
    }

    [TestMethod]
    public void AMissingIncludedFile_IsIgnored_AsOpenSshDoes()
    {
        Assert.AreEqual(CheckStatus.Pass, Check.Run(Config("Include nothing-here\nInclude conf.d/*\n")).Status);
    }

    [TestMethod]
    public void AnIncludeThatLoopsBackOnItself_Ends()
    {
        FakeProbes probes = Config("Include config\n");

        Assert.AreEqual(CheckStatus.Error, Check.Run(probes).Status);
    }

    [TestMethod]
    [DataRow("Include ${HOME}/x\n", "variable")]
    [DataRow("Include %d/x\n", "variable")]
    [DataRow("Include */config\n", "wildcard")]
    [DataRow("Include //server.example/share/config\n", "another computer")]
    [DataRow("Include \\\\server.example\\share\\*.conf\n", "another computer")]
    [DataRow("Host \"unclosed\n", "quote")]
    public void WhatCannotBeFollowed_IsCouldNotCheck_WithTheLine(string text, string reason)
    {
        CheckOutcome outcome = Check.Run(Config(text));

        Assert.AreEqual(CheckStatus.Error, outcome.Status);
        StringAssert.Contains(outcome.Summary, "config, line 1");
        StringAssert.Contains(outcome.Summary, reason);
    }

    [TestMethod]
    public void WhatCannotBeFollowed_DoesNotHideADefiniteProblem()
    {
        Assert.AreEqual(CheckStatus.Fail, Check.Run(Config("Include ${HOME}/x\nForwardAgent yes\n")).Status);
    }

    [TestMethod]
    public void AnUnreadableSettingsFile_IsCouldNotCheck()
    {
        FakeProbes probes = new FakeProbes().WithFileFailure(SshFixtures.Path("config"), ProbeFailure.AccessDenied());

        CheckOutcome outcome = Check.Run(probes);

        Assert.AreEqual(CheckStatus.Error, outcome.Status);
        StringAssert.Contains(outcome.Summary, "config could not be read");
    }

    [TestMethod]
    public void SplitLine_HandlesQuotesEqualsAndComments()
    {
        Assert.AreEqual(("forwardagent", "yes"), Flat(SshConfigFile.SplitLine("ForwardAgent=yes")));
        Assert.AreEqual(("forwardagent", "yes"), Flat(SshConfigFile.SplitLine("ForwardAgent = yes")));
        Assert.AreEqual(("identityfile", "C:\\my keys\\id"), Flat(SshConfigFile.SplitLine("IdentityFile \"C:\\my keys\\id\"")));
        Assert.AreEqual(("host", "a|b"), Flat(SshConfigFile.SplitLine("Host a b # two hosts")));
        Assert.AreEqual((string.Empty, string.Empty), Flat(SshConfigFile.SplitLine("   # only a comment")));
        Assert.IsNull(SshConfigFile.SplitLine("Host \"open"));
    }

    private static (string, string) Flat((string Keyword, List<string> Arguments)? line) =>
        (line!.Value.Keyword, string.Join('|', line.Value.Arguments));
}
