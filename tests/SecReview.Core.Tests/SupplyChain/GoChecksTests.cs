using SecReview.Checks;
using SecReview.Probing;
using SecReview.SupplyChain;
using SecReview.SupplyChain.Go;
using SecReview.Tests.Checks;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.SupplyChain;

[TestClass]
public sealed class GoChecksTests
{
    private static readonly string EnvFile = FakeProbes.FolderPath(KnownFolder.RoamingAppData) + @"\go\env";

    private static readonly GoSettingsCheck Check = new();

    /// <summary>A PC with Go and the given lines in Go's own settings file.</summary>
    private static FakeProbes Go(string env = "GOPATH=D:\\go\n") => new FakeProbes().WithFile(EnvFile, env);

    private static FakeProbes WithVariable(FakeProbes probes, string name, string value) =>
        probes.WithRegistryValue(RegistryRoot.CurrentUser, PersistentEnvironment.UserKey, name, RegistryValue.FromText(value));

    [TestMethod]
    public void WithoutGo_TheCheckDoesNotApply_AndItNeverRunsElevated()
    {
        Assert.AreEqual(CheckStatus.NotApplicable, Check.Run(new FakeProbes()).Status);
        Assert.AreEqual(CheckScope.User, Check.Definition.Scope);

        // A folder Go's tools leave behind is not Go.
        FakeProbes telemetryOnly = new FakeProbes().WithFile(FakeProbes.FolderPath(KnownFolder.RoamingAppData) + @"\go\telemetry\local\weekends", "x");
        Assert.AreEqual(CheckStatus.NotApplicable, Check.Run(telemetryOnly).Status);
    }

    [TestMethod]
    public void GoIsFound_ByItsInstallFolder_ItsWorkFolder_OrAVariable()
    {
        Assert.AreEqual(CheckStatus.Pass, Check.Run(new FakeProbes().WithFile(@"C:\Program Files\Go\VERSION", "go1.25.3")).Status);
        Assert.AreEqual(CheckStatus.Pass, Check.Run(new FakeProbes().WithFile(FakeProbes.UserProfile + @"\go\pkg\mod\cache\lock", "")).Status);
        Assert.AreEqual(CheckStatus.Pass, Check.Run(WithVariable(new FakeProbes(), "GOPROXY", "https://proxy.golang.org,direct")).Status);
    }

    [TestMethod]
    public void Defaults_Pass()
    {
        CheckOutcome outcome = Check.Run(Go());

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("Go verifies every module against the checksum database, over HTTPS.", outcome.Summary);
    }

    [TestMethod]
    [DataRow("GOINSECURE=git.example.test", "Go: modules fetched without TLS checks: 1 pattern.")]
    [DataRow("GOINSECURE=git.example.test,*.internal.example", "Go: modules fetched without TLS checks: 2 patterns.")]
    [DataRow("GOSUMDB=off", "Go: checksum database: off.")]
    [DataRow("GONOSUMDB=*", "Go: checksum database: skipped for every module (GONOSUMDB).")]
    [DataRow("GOPRIVATE=git.example.test,*", "Go: checksum database: skipped for every module (GOPRIVATE).")]
    [DataRow("GOPROXY=http://proxy.example.test,direct", "Go: module proxy: plain HTTP.")]
    public void EachWeakSetting_Fails_AndIsNamed(string line, string summary)
    {
        CheckOutcome outcome = Check.Run(Go("GOPATH=D:\\go\n" + line + "\n"));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual(summary, outcome.Summary);
        Assert.AreEqual($"{EnvFile}, line 2", outcome.Findings[0].Source);
    }

    [TestMethod]
    [DataRow("*.*")]
    [DataRow("*")]
    [DataRow("*/*")]
    [DataRow("*.???")]
    [DataRow("git.example.test,*.*")]
    public void AnExemptionThatMatchesEveryHost_Fails_HoweverItIsWritten(string patterns)
    {
        Assert.AreEqual(CheckStatus.Fail, Check.Run(Go("GONOSUMDB=" + patterns + "\n")).Status);
    }

    [TestMethod]
    [DataRow("*.example.test")]
    [DataRow("github.com/company/*")]
    public void AnExemptionForOnesOwnHosts_DoesNotMatchEveryHost(string pattern)
    {
        Assert.IsFalse(GoSettingsCheck.MatchesEveryHost(pattern));
    }

    [TestMethod]
    public void ExemptionsForPrivateModules_AreListed_NotFailed()
    {
        CheckOutcome outcome = Check.Run(Go("GOPRIVATE=git.example.test/*\nGOSUMDB=sum.golang.org\nGOPROXY=https://proxy.golang.org|direct\n"));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("Modules exempt from the checksum database (GOPRIVATE): 1 pattern [note]", outcome.Rows()[^1]);
        Assert.IsFalse(outcome.Rows().Any(r => r.Contains("example.test", StringComparison.Ordinal)), "the patterns themselves are not shown");
    }

    [TestMethod]
    public void AVariable_WinsOverTheFile_AndTheFileCanBeMovedOrSwitchedOff()
    {
        CheckOutcome overridden = Check.Run(WithVariable(Go("GOSUMDB=off\n"), "GOSUMDB", "sum.golang.org"));
        Assert.AreEqual(CheckStatus.Pass, overridden.Status);

        CheckOutcome byVariable = Check.Run(WithVariable(Go(), "GOINSECURE", "git.example.test"));
        Assert.AreEqual(CheckStatus.Fail, byVariable.Status);
        StringAssert.Contains(byVariable.Findings[0].Source, "GOINSECURE");

        const string Moved = @"D:\settings\goenv";
        FakeProbes moved = WithVariable(Go(), "GOENV", Moved).WithFile(Moved, "GOSUMDB=off\n");
        Assert.AreEqual(CheckStatus.Fail, Check.Run(moved).Status);

        FakeProbes off = WithVariable(Go("GOSUMDB=off\n"), "GOENV", "off");
        Assert.AreEqual(CheckStatus.Pass, Check.Run(off).Status, "with GOENV=off the file is not read");
    }

    [TestMethod]
    public void SeveralProblems_AreCounted_AndAnUnreadableFileIsCouldNotCheck()
    {
        Assert.AreEqual(
            "Go has 2 settings that weaken how it verifies modules.", Check.Run(Go("GOSUMDB=off\nGOINSECURE=x\n")).Summary);
        Assert.AreEqual(CheckStatus.Error, Check.Run(new FakeProbes().WithFileFailure(EnvFile, ProbeFailure.AccessDenied())).Status);
    }
}
