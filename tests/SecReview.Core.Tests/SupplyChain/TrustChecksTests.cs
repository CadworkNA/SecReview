using SecReview.Checks;
using SecReview.Probing;
using SecReview.SupplyChain.Trust;
using SecReview.Tests.Checks;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.SupplyChain;

[TestClass]
public sealed class TrustChecksTests
{
    private static readonly RootCertificatesCheck Roots = new();

    private static FakeProbes WithRoot(FakeProbes probes, string thumbprint) => probes.WithRegistryValue(
        RegistryRoot.CurrentUser, $@"{RootCertificatesCheck.UserRoots}\{thumbprint}", "Blob", RegistryValue.FromBinary([1, 2, 3]));

    private static string Thumbprint(int number) => number.ToString("x2", System.Globalization.CultureInfo.InvariantCulture).PadLeft(40, 'a');

    [TestMethod]
    public void Roots_NoneAddedForTheAccount_Pass()
    {
        CheckOutcome outcome = Roots.Run(new FakeProbes());

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("No certificate authority is trusted for your account alone.", outcome.Summary);
        Assert.AreEqual(CheckScope.User, Roots.Definition.Scope);
    }

    [TestMethod]
    public void Roots_AddedForTheAccount_AreListedByThumbprint_NotFailed()
    {
        CheckOutcome one = Roots.Run(WithRoot(new FakeProbes(), Thumbprint(1)));
        Assert.AreEqual(CheckStatus.Pass, one.Status);
        Assert.AreEqual("1 certificate authority is trusted for your account alone; check that you know it.", one.Summary);
        Assert.AreEqual($"Certificate authority added for your account: Thumbprint {Thumbprint(1).ToUpperInvariant()} [note]", one.Rows()[0]);

        CheckOutcome two = Roots.Run(WithRoot(WithRoot(new FakeProbes(), Thumbprint(1)), Thumbprint(2)));
        Assert.AreEqual("2 certificate authorities are trusted for your account alone; check that you know each.", two.Summary);
    }

    [TestMethod]
    public void Roots_KeysThatAreNotCertificates_AreIgnored_AndManyAreCutShort()
    {
        FakeProbes other = new FakeProbes().WithRegistryValue(
            RegistryRoot.CurrentUser, $@"{RootCertificatesCheck.UserRoots}\NotAThumbprint", "Blob", RegistryValue.FromBinary([1]));
        Assert.AreEqual("No certificate authority is trusted for your account alone.", Roots.Run(other).Summary);

        var many = new FakeProbes();
        for (int i = 0; i < 13; i++)
        {
            WithRoot(many, Thumbprint(i));
        }

        CheckOutcome outcome = Roots.Run(many);
        Assert.AreEqual(11, outcome.Findings.Count);
        Assert.AreEqual("More certificate authorities: 3 more [note]", outcome.Rows()[^1]);
    }

    [TestMethod]
    public void Roots_WhenTheRegistryCannotBeRead_IsCouldNotCheck()
    {
        var probes = new FakeProbes { RegistryFailure = ProbeFailure.Failed("The registry did not answer.") };

        Assert.AreEqual(CheckStatus.Error, Roots.Run(probes).Status);
    }
}
