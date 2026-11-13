using SecReview.Checks;
using SecReview.Checks.BuiltIn;
using SecReview.Probing;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.Checks;

/// <summary>Revocation checking and the proxy configuration script. Every address here is made up.</summary>
[TestClass]
public sealed class TrustSettingsChecksTests
{
    /// <summary>What Windows writes for the publisher setting when nothing was changed.</summary>
    private const long UsualState = 0x23C00;

    private static readonly RevocationCheck Revocation = new();
    private static readonly ProxyCheck Proxy = new();

    private static FakeProbes State(long state) =>
        new FakeProbes().WithRegistryNumber(RegistryRoot.CurrentUser, RevocationCheck.PublisherKey, RevocationCheck.PublisherValue, state);

    private static FakeProbes Server(FakeProbes probes, long value, RegistryRoot root = RegistryRoot.CurrentUser, bool policy = false) =>
        probes.WithRegistryNumber(root, policy ? RevocationCheck.ServerPolicyKey : RevocationCheck.ServerKey, RevocationCheck.ServerValue, value);

    private static FakeProbes Text(FakeProbes probes, RegistryRoot root, string key, string name, string value) =>
        probes.WithRegistryValue(root, key, name, RegistryValue.FromText(value));

    private static FakeProbes Script(string address, RegistryRoot root = RegistryRoot.CurrentUser, string key = ProxyCheck.UserKey) =>
        Text(new FakeProbes(), root, key, ProxyCheck.ScriptValue, address);

    // Revocation

    [TestMethod]
    public void Revocation_NothingSet_OrTheUsualValues_Pass()
    {
        CheckOutcome unset = Revocation.Run(new FakeProbes());
        CheckOutcome usual = Revocation.Run(Server(State(UsualState), 1));

        Assert.AreEqual(CheckStatus.Pass, unset.Status);
        Assert.AreEqual("Windows checks whether certificates were revoked.", unset.Summary);
        CollectionAssert.AreEqual(
            (string[])
            [
                "Revocation check for signed programs: On (Windows default) (expected On) [ok]",
                "Revocation check for websites: On (Windows default) (expected On) [ok]",
            ],
            unset.Rows());
        Assert.AreEqual(CheckStatus.Pass, usual.Status);
        Assert.AreEqual("Revocation check for signed programs: On (expected On) [ok]", usual.Rows()[0]);
    }

    [TestMethod]
    public void Revocation_SwitchedOffForSignedPrograms_Fails()
    {
        CheckOutcome outcome = Revocation.Run(State(UsualState | RevocationCheck.IgnoreRevocation));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("Windows does not check whether certificates of signed programs were revoked.", outcome.Summary);
        Assert.AreEqual("Revocation check for signed programs: Off (expected On) [problem]", outcome.Rows()[0]);
        Assert.AreEqual($@"HKCU\{RevocationCheck.PublisherKey}\{RevocationCheck.PublisherValue}", outcome.Findings[0].Source);
        Assert.IsFalse(outcome.ManagedByPolicy);
    }

    [TestMethod]
    public void Revocation_SwitchedOffForWebsites_Fails_AndBoth_SaysBoth()
    {
        CheckOutcome websites = Revocation.Run(Server(State(UsualState), 0));
        CheckOutcome both = Revocation.Run(Server(State(UsualState | RevocationCheck.IgnoreRevocation), 0));

        Assert.AreEqual(CheckStatus.Fail, websites.Status);
        Assert.AreEqual("Windows does not check whether certificates of websites were revoked.", websites.Summary);
        Assert.AreEqual("Windows does not check whether certificates of signed programs and websites were revoked.", both.Summary);
    }

    [TestMethod]
    [DataRow(RegistryRoot.LocalMachine)]
    [DataRow(RegistryRoot.CurrentUser)]
    public void Revocation_APolicyWinsOverTheUsersSetting_AndIsMarkedAsManaged(RegistryRoot root)
    {
        CheckOutcome off = Revocation.Run(Server(Server(new FakeProbes(), 1), 0, root, policy: true));
        CheckOutcome on = Revocation.Run(Server(Server(new FakeProbes(), 0), 1, root, policy: true));

        Assert.AreEqual(CheckStatus.Fail, off.Status);
        Assert.IsTrue(off.ManagedByPolicy);
        StringAssert.Contains(off.Findings[1].Source, @"\Policies\");
        Assert.AreEqual(CheckStatus.Pass, on.Status);
    }

    [TestMethod]
    public void Revocation_ASettingThatCannotBeRead_IsCouldNotCheck()
    {
        FakeProbes notANumber = Text(new FakeProbes(), RegistryRoot.CurrentUser, RevocationCheck.PublisherKey, RevocationCheck.PublisherValue, "on");
        var failed = new FakeProbes { RegistryFailure = ProbeFailure.Failed("The registry did not answer.") };

        Assert.AreEqual(CheckStatus.Error, Revocation.Run(notANumber).Status);
        Assert.AreEqual(CheckStatus.Error, Revocation.Run(failed).Status);
        Assert.AreEqual(CheckCategory.Hardening, Revocation.Definition.Category);
        Assert.AreEqual(CheckScope.User, Revocation.Definition.Scope);
    }

    // Proxy

    [TestMethod]
    public void Proxy_NoScript_Passes()
    {
        CheckOutcome outcome = Proxy.Run(new FakeProbes());

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("No proxy configuration script is set.", outcome.Summary);
        Assert.AreEqual("Proxy configuration script: None (expected None, or fetched over HTTPS) [ok]", outcome.Rows()[0]);
        Assert.AreEqual(CheckScope.User, Proxy.Definition.Scope);
    }

    [TestMethod]
    public void Proxy_AScriptOverHttps_Passes_ShowingTheHostOnly()
    {
        CheckOutcome outcome = Proxy.Run(Script("https://user:made-up@proxy.example.test:8443/files/proxy.pac?site=north"));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("The proxy configuration script is fetched over a protected connection.", outcome.Summary);
        Assert.AreEqual("Fetched from proxy.example.test", outcome.Findings[0].Found);
    }

    [TestMethod]
    [DataRow("http://proxy.example.test/proxy.pac")]
    [DataRow("HTTP://proxy.example.test:8080/proxy.pac?site=north")]
    public void Proxy_AScriptOverPlainHttp_Fails(string address)
    {
        CheckOutcome outcome = Proxy.Run(Script(address));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("The proxy configuration script is fetched over plain HTTP.", outcome.Summary);
        Assert.AreEqual("Fetched over plain HTTP from proxy.example.test", outcome.Findings[0].Found);
        Assert.AreEqual($@"HKCU\{ProxyCheck.UserKey}\{ProxyCheck.ScriptValue}", outcome.Findings[0].Source);
        Assert.IsFalse(outcome.ManagedByPolicy);
    }

    [TestMethod]
    [DataRow(RegistryRoot.LocalMachine, ProxyCheck.PolicyKey, true)]
    [DataRow(RegistryRoot.CurrentUser, ProxyCheck.PolicyKey, true)]
    [DataRow(RegistryRoot.LocalMachine, ProxyCheck.UserKey, false)]
    public void Proxy_AScriptSetForThePcOrByPolicy_IsJudgedToo(RegistryRoot root, string key, bool managed)
    {
        CheckOutcome outcome = Proxy.Run(Script("http://proxy.example.test/proxy.pac", root, key));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual(managed, outcome.ManagedByPolicy);
        StringAssert.StartsWith(outcome.Findings[0].Source, root == RegistryRoot.LocalMachine ? @"HKLM\" : @"HKCU\");
    }

    [TestMethod]
    public void Proxy_AFixedProxy_IsListedByHost_NotJudged_AndOnlyWhenSwitchedOn()
    {
        FakeProbes on = Text(new FakeProbes(), RegistryRoot.CurrentUser, ProxyCheck.UserKey, ProxyCheck.ServerValue, "http=proxy.example.test:3128;https=other.example.test:3128")
            .WithRegistryNumber(RegistryRoot.CurrentUser, ProxyCheck.UserKey, ProxyCheck.EnabledValue, 1);
        FakeProbes off = Text(new FakeProbes(), RegistryRoot.CurrentUser, ProxyCheck.UserKey, ProxyCheck.ServerValue, "proxy.example.test:3128")
            .WithRegistryNumber(RegistryRoot.CurrentUser, ProxyCheck.UserKey, ProxyCheck.EnabledValue, 0);

        CheckOutcome outcome = Proxy.Run(on);

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("No proxy configuration script is set.", outcome.Summary);
        CollectionAssert.Contains(outcome.Rows(), "Fixed proxy: proxy.example.test [note]");
        Assert.AreEqual(1, Proxy.Run(off).Findings.Count);
    }

    [TestMethod]
    [DataRow("proxy.example.test:3128", "proxy.example.test")]
    [DataRow("https=proxy.example.test:3128;http=other.example.test", "proxy.example.test")]
    [DataRow("http://user:made-up@proxy.example.test:8080/a/b?c=d", "proxy.example.test")]
    [DataRow("socks=127.0.0.1:1080", "127.0.0.1")]
    [DataRow("[::1]:8080", "[::1]")]
    [DataRow("proxy.example.test", "proxy.example.test")]
    [DataRow("", "one address")]
    [DataRow("not a host <at all>", "one address")]
    public void Proxy_Host_IsTheHostAndNothingElse(string text, string expected)
    {
        Assert.AreEqual(expected, ProxyCheck.Host(text));
    }

    [TestMethod]
    public void Proxy_ASettingThatCannotBeRead_IsCouldNotCheck()
    {
        FakeProbes notText = new FakeProbes().WithRegistryNumber(RegistryRoot.CurrentUser, ProxyCheck.UserKey, ProxyCheck.ScriptValue, 1);
        var failed = new FakeProbes { RegistryFailure = ProbeFailure.Failed("The registry did not answer.") };

        Assert.AreEqual(CheckStatus.Error, Proxy.Run(notText).Status);
        Assert.AreEqual(CheckStatus.Error, Proxy.Run(failed).Status);
    }
}
