using SecReview.Checks;
using SecReview.Probing;
using SecReview.SupplyChain;
using SecReview.SupplyChain.Variables;
using SecReview.Tests.Checks;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.SupplyChain;

/// <summary>Checks on environment variables that are set for good.</summary>
[TestClass]
public sealed class EnvironmentChecksTests
{
    private static readonly EnvironmentTlsCheck Tls = new();
    private static readonly EnvironmentInjectionCheck Injection = new();
    private static readonly EnvironmentTokensCheck Tokens = new();

    private static FakeProbes With(string name, string value, FakeProbes? probes = null) =>
        (probes ?? new FakeProbes()).WithRegistryValue(RegistryRoot.CurrentUser, PersistentEnvironment.UserKey, name, RegistryValue.FromText(value));

    private static FakeProbes ForThePc(string name, string value) =>
        new FakeProbes().WithRegistryValue(RegistryRoot.LocalMachine, PersistentEnvironment.MachineKey, name, RegistryValue.FromText(value));

    private static string Everything(CheckOutcome outcome) =>
        outcome.Summary + string.Join('|', outcome.Findings.Select(f => f.Item + f.Found + f.Expected + f.Source));

    [TestMethod]
    public void WithNothingSet_AllPass_AndNoneRunsElevated()
    {
        foreach (ICheck check in new ICheck[] { Tls, Injection, Tokens })
        {
            Assert.AreEqual(CheckStatus.Pass, check.Run(new FakeProbes()).Status, check.Definition.Id);
            Assert.AreEqual(CheckScope.User, check.Definition.Scope);
            Assert.AreEqual(CheckCategory.SupplyChain, check.Definition.Category);
        }
    }

    [TestMethod]
    public void WhenTheVariablesCannotBeRead_AllAreCouldNotCheck()
    {
        var probes = new FakeProbes { RegistryFailure = ProbeFailure.Failed("The registry did not answer.") };

        foreach (ICheck check in new ICheck[] { Tls, Injection, Tokens })
        {
            Assert.AreEqual(CheckStatus.Error, check.Run(probes).Status, check.Definition.Id);
        }
    }

    // TLS

    [TestMethod]
    [DataRow("NODE_TLS_REJECT_UNAUTHORIZED", "0", "Node.js TLS certificate checks are switched off by a permanent variable.")]
    [DataRow("GIT_SSL_NO_VERIFY", "true", "Git TLS certificate checks are switched off by a permanent variable.")]
    [DataRow("GIT_SSL_NO_VERIFY", "false", "Git TLS certificate checks are switched off by a permanent variable.")]
    [DataRow("git_ssl_no_verify", "1", "Git TLS certificate checks are switched off by a permanent variable.")]
    public void Tls_AVariableThatSwitchesChecksOff_Fails(string name, string value, string summary)
    {
        CheckOutcome outcome = Tls.Run(With(name, value));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual(summary, outcome.Summary);
        StringAssert.Contains(outcome.Findings[0].Source, name);
    }

    [TestMethod]
    public void Tls_NodeIsOnlySwitchedOffByZero()
    {
        Assert.AreEqual(CheckStatus.Pass, Tls.Run(With("NODE_TLS_REJECT_UNAUTHORIZED", "1")).Status);
        Assert.AreEqual(CheckStatus.Pass, Tls.Run(With("NODE_TLS_REJECT_UNAUTHORIZED", "")).Status);
    }

    [TestMethod]
    public void Tls_BothSwitchedOff_SaysSo_AndThePcsVariablesCountToo()
    {
        FakeProbes probes = ForThePc("NODE_TLS_REJECT_UNAUTHORIZED", "0")
            .WithRegistryValue(RegistryRoot.CurrentUser, PersistentEnvironment.UserKey, "GIT_SSL_NO_VERIFY", RegistryValue.FromText("1"));

        CheckOutcome outcome = Tls.Run(probes);

        Assert.AreEqual("TLS certificate checks are switched off for Node.js and Git by permanent variables.", outcome.Summary);
        StringAssert.StartsWith(outcome.Findings[0].Source, "the PC's environment variables");
    }

    [TestMethod]
    public void Tls_ReplacedCertificateAuthorities_AreListed_NotFailed()
    {
        CheckOutcome outcome = Tls.Run(With("NODE_EXTRA_CA_CERTS", @"C:\certs\proxy.pem", With("SSL_CERT_FILE", @"C:\certs\all.pem")));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("No variable switches off TLS checks; 2 change which certificate authorities are trusted.", outcome.Summary);
        CollectionAssert.AreEqual(
            new[]
            {
                "TLS certificate checks: Not switched off (expected On) [ok]",
                "Certificate authorities for OpenSSL-based tools: Replaced by a file you chose [note]",
                "Certificate authorities for Node.js: Extended by a file you chose [note]",
            },
            outcome.Rows());
        Assert.IsFalse(Everything(outcome).Contains(".pem", StringComparison.Ordinal), "the value is not shown");
    }

    // Code loaded by variables

    [TestMethod]
    [DataRow("NODE_OPTIONS", "--require C:\\tools\\hook.js", "NODE_OPTIONS")]
    [DataRow("NODE_OPTIONS", "--max-old-space-size=4096 --import=file:///C:/tools/hook.mjs", "NODE_OPTIONS")]
    [DataRow("NODE_OPTIONS", "-r ./hook", "NODE_OPTIONS")]
    [DataRow("DOTNET_STARTUP_HOOKS", "C:\\tools\\hook.dll", "DOTNET_STARTUP_HOOKS")]
    [DataRow("JAVA_TOOL_OPTIONS", "-Xmx2g -javaagent:C:\\tools\\agent.jar", "JAVA_TOOL_OPTIONS")]
    [DataRow("_JAVA_OPTIONS", "-agentlib:something", "_JAVA_OPTIONS")]
    [DataRow("BASH_ENV", "C:\\tools\\env.sh", "BASH_ENV")]
    [DataRow("PERL5OPT", "-MSomething", "PERL5OPT")]
    [DataRow("RUBYOPT", "-rsomething", "RUBYOPT")]
    public void Injection_AVariableThatLoadsCode_Fails_AndIsNamed(string name, string value, string named)
    {
        CheckOutcome outcome = Injection.Run(With(name, value));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual($"A permanent variable loads code into every program of one kind: {named}.", outcome.Summary);
        Assert.IsFalse(Everything(outcome).Contains("tools", StringComparison.Ordinal), "the value is not shown");
    }

    [TestMethod]
    [DataRow("NODE_OPTIONS", "--max-old-space-size=4096")]
    [DataRow("NODE_OPTIONS", "--report-on-signal")]
    [DataRow("JAVA_TOOL_OPTIONS", "-Xmx2g -Dfile.encoding=UTF-8")]
    [DataRow("DOTNET_STARTUP_HOOKS", "  ")]
    [DataRow("RUBYOPT", "-W0")]
    public void Injection_OrdinaryOptions_Pass(string name, string value)
    {
        Assert.AreEqual(CheckStatus.Pass, Injection.Run(With(name, value)).Status);
    }

    [TestMethod]
    public void Injection_AProfiler_CountsOnlyWhenSwitchedOn()
    {
        const string Id = "{11111111-2222-3333-4444-555555555555}";

        Assert.AreEqual(CheckStatus.Pass, Injection.Run(With("CORECLR_PROFILER", Id)).Status, "named but not switched on");
        Assert.AreEqual(CheckStatus.Pass, Injection.Run(With("CORECLR_ENABLE_PROFILING", "0", With("CORECLR_PROFILER", Id))).Status);

        CheckOutcome on = Injection.Run(With("CORECLR_ENABLE_PROFILING", "1", With("CORECLR_PROFILER", Id)));
        Assert.AreEqual(CheckStatus.Fail, on.Status);
        Assert.AreEqual(".NET profiler (CORECLR_PROFILER)", on.Findings[0].Item);

        CheckOutcome framework = Injection.Run(With("COR_ENABLE_PROFILING", "1", With("COR_PROFILER", Id)));
        Assert.AreEqual(".NET Framework profiler (COR_PROFILER)", framework.Findings[0].Item);
    }

    [TestMethod]
    [DataRow("01")]
    [DataRow("0x1")]
    [DataRow("F")]
    public void Injection_AProfilerSwitch_IsOnForAnyNumberButZero(string value)
    {
        FakeProbes probes = With("CORECLR_ENABLE_PROFILING", value, With("CORECLR_PROFILER", "{11111111-2222-3333-4444-555555555555}"));

        Assert.AreEqual(CheckStatus.Fail, Injection.Run(probes).Status);
    }

    [TestMethod]
    public void Injection_JavaOptionsTakenFromAFile_Fail_BecauseTheFileMayLoadAnAgent()
    {
        CheckOutcome outcome = Injection.Run(With("JDK_JAVA_OPTIONS", "-Xmx2g @D:/java/options.txt"));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        StringAssert.Contains(outcome.Findings[0].Found, "from a file");
    }

    [TestMethod]
    public void Injection_CommonMilderVariables_AreListed_NotFailed()
    {
        CheckOutcome outcome = Injection.Run(With("PYTHONPATH", @"D:\lib", With("RUSTC_WRAPPER", "sccache")));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("No variable loads code into your tools; 2 change how tools start.", outcome.Summary);
        Assert.AreEqual(2, outcome.Findings.Count(f => f.Status == FindingStatus.Note));
    }

    [TestMethod]
    public void Injection_SeveralProblems_AreCounted()
    {
        CheckOutcome outcome = Injection.Run(With("NODE_OPTIONS", "--require x", With("DOTNET_STARTUP_HOOKS", "x.dll")));

        Assert.AreEqual("2 permanent variables load code into every program of one kind.", outcome.Summary);
    }

    // Tokens

    [TestMethod]
    [DataRow("GITHUB_TOKEN")]
    [DataRow("GH_TOKEN")]
    [DataRow("github_pat")]
    [DataRow("NUGET_API_KEY")]
    [DataRow("AWS_SECRET_ACCESS_KEY")]
    [DataRow("AZURE_CLIENT_SECRET")]
    [DataRow("TWINE_PASSWORD")]
    [DataRow("CARGO_REGISTRY_TOKEN")]
    [DataRow("SOME_SERVICE_APIKEY")]
    public void Tokens_AVariableNamedLikeASecret_Fails_NamingItOnly(string name)
    {
        CheckOutcome outcome = Tokens.Run(With(name, "made-up-secret"));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("1 permanent variable holds a token or password.", outcome.Summary);
        Assert.AreEqual($"Variable {name}", outcome.Findings[0].Item);
        Assert.IsFalse(Everything(outcome).Contains("made-up", StringComparison.Ordinal), "the secret itself never appears");
    }

    [TestMethod]
    [DataRow("AWS_ACCESS_KEY_ID", "made-up")]
    [DataRow("GITHUB_TOKEN", "")]
    [DataRow("GITHUB_TOKEN", "   ")]
    [DataRow("SSH_PRIVATE_KEY", @"C:\keys\id_ed25519")]
    [DataRow("SERVICE_TOKEN", @"\\server\share\token.txt")]
    [DataRow("TOKENIZERS_PARALLELISM", "false")]
    [DataRow("PATH", @"C:\Windows")]
    public void Tokens_OtherVariables_EmptyOnes_AndFilePaths_Pass(string name, string value)
    {
        Assert.AreEqual(CheckStatus.Pass, Tokens.Run(With(name, value)).Status);
    }

    [TestMethod]
    public void Tokens_SeveralAreCounted_AndThePcsVariablesCountToo()
    {
        FakeProbes probes = With("GITHUB_TOKEN", "made-up", ForThePc("NUGET_API_KEY", "made-up"));

        CheckOutcome outcome = Tokens.Run(probes);

        Assert.AreEqual("2 permanent variables hold tokens or passwords.", outcome.Summary);
    }

    [TestMethod]
    [DataRow("NPM_TOKEN")]
    [DataRow("NODE_AUTH_TOKEN")]
    [DataRow("npm_config_//registry.npmjs.org/:_authToken")]
    [DataRow("YARN_NPM_AUTH_TOKEN")]
    public void Tokens_VariablesTheNpmAndYarnChecksReport_AreLeftToThem(string name)
    {
        Assert.AreEqual(CheckStatus.Pass, Tokens.Run(With(name, "made-up")).Status);
    }

    [TestMethod]
    public void Tokens_AToolsOwnVariable_IsReportedHere_OnlyWhenTheToolsCheckDoesNotApply()
    {
        // Without uv, nothing else would report uv's token.
        Assert.AreEqual(CheckStatus.Fail, Tokens.Run(With("UV_PUBLISH_TOKEN", "made-up")).Status);

        // With uv, its own check does.
        FakeProbes withUv = With("UV_PUBLISH_TOKEN", "made-up")
            .WithFile(FakeProbes.FolderPath(KnownFolder.RoamingAppData) + @"\uv\uv.toml", "exclude-newer = \"7 days\"");
        Assert.AreEqual(CheckStatus.Pass, Tokens.Run(withUv).Status);

        Assert.AreEqual(CheckStatus.Fail, Tokens.Run(With("SCOOP_GH_TOKEN", "made-up")).Status);
        FakeProbes withScoop = With("SCOOP_GH_TOKEN", "made-up").WithFile(FakeProbes.UserProfile + @"\scoop\apps\scoop\current\bin\scoop.ps1", "#");
        Assert.AreEqual(CheckStatus.Pass, Tokens.Run(withScoop).Status);

        // A uv variable its check does not know is still reported.
        FakeProbes other = With("UV_SOMETHING_TOKEN", "made-up")
            .WithFile(FakeProbes.FolderPath(KnownFolder.RoamingAppData) + @"\uv\uv.toml", "exclude-newer = \"7 days\"");
        Assert.AreEqual(CheckStatus.Fail, Tokens.Run(other).Status);
    }
}
