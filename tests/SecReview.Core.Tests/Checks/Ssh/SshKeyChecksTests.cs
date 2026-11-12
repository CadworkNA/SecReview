using SecReview.Checks;
using SecReview.Checks.BuiltIn.Ssh;
using SecReview.Probing;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.Checks.Ssh;

[TestClass]
public sealed class SshKeyChecksTests
{
    private static readonly SshKeyPassphraseCheck Passphrase = new();
    private static readonly SshKeyStrengthCheck Strength = new();

    private static FakeProbes Keys(params (string Name, string Text)[] files)
    {
        var probes = new FakeProbes();
        foreach ((string name, string text) in files)
        {
            probes.WithFile(SshFixtures.Path(name), text);
        }

        return probes;
    }

    [TestMethod]
    public void BothChecks_ReadTheUsersOwnFiles_SoNeverRunElevated()
    {
        Assert.AreEqual(CheckScope.User, Passphrase.Definition.Scope);
        Assert.AreEqual(CheckScope.User, Strength.Definition.Scope);
    }

    [TestMethod]
    public void NoSshFolder_DoesNotApply()
    {
        Assert.AreEqual(CheckStatus.NotApplicable, Passphrase.Run(new FakeProbes()).Status);
        Assert.AreEqual(CheckStatus.NotApplicable, Strength.Run(new FakeProbes()).Status);
    }

    [TestMethod]
    public void AFolderWithoutPrivateKeys_DoesNotApply()
    {
        FakeProbes probes = Keys(
            ("config", "Host *\n"),
            ("known_hosts", "example.com ssh-ed25519 AAAA\n"),
            ("id_ed25519.pub", SshFixtures.PublicLine(SshFixtures.Ed25519Blob())),
            ("notes.txt", "not a key"));

        Assert.AreEqual(CheckStatus.NotApplicable, Passphrase.Run(probes).Status);
    }

    [TestMethod]
    public void TheFolderCannotBeListed_IsCouldNotCheck_NeverAPass()
    {
        FakeProbes probes = new FakeProbes().WithFolderFailure(SshFixtures.Folder, ProbeFailure.Failed("Listing the folder failed."));

        Assert.AreEqual(CheckStatus.Error, Passphrase.Run(probes).Status);
        Assert.AreEqual(CheckStatus.Error, Strength.Run(probes).Status);
    }

    [TestMethod]
    public void AllKeysProtected_Passes()
    {
        FakeProbes probes = Keys(
            ("id_ed25519", SshFixtures.OpenSsh(SshFixtures.Ed25519Blob(), passphrase: true)),
            ("work", SshFixtures.LegacyPem("RSA", passphrase: true)));

        CheckOutcome outcome = Passphrase.Run(probes);

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("All 2 SSH keys are protected.", outcome.Summary);
    }

    [TestMethod]
    public void AKeyWithoutPassphrase_Fails_AndIsNamed()
    {
        FakeProbes probes = Keys(
            ("id_ed25519", SshFixtures.OpenSsh(SshFixtures.Ed25519Blob(), passphrase: true)),
            ("id_rsa", SshFixtures.OpenSsh(SshFixtures.RsaBlob(4096), passphrase: false)));

        CheckOutcome outcome = Passphrase.Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("id_rsa has no passphrase.", outcome.Summary);
        CollectionAssert.AreEqual(
            new[]
            {
                "id_ed25519: Passphrase (expected Passphrase) [ok]",
                "id_rsa: No passphrase (expected Passphrase) [problem]",
            },
            outcome.Rows());
    }

    [TestMethod]
    public void AKeyOnAHardwareSecurityKey_NeedsNoPassphrase()
    {
        FakeProbes probes = Keys(("id_ed25519_sk", SshFixtures.OpenSsh(SshFixtures.SecurityKeyBlob(), passphrase: false)));

        Assert.AreEqual(CheckStatus.Pass, Passphrase.Run(probes).Status);
        Assert.AreEqual(CheckStatus.Pass, Strength.Run(probes).Status);
    }

    [TestMethod]
    public void AKeyFileThatCannotBeUnderstood_IsCouldNotCheck_NotAPass()
    {
        FakeProbes probes = Keys(
            ("good", SshFixtures.OpenSsh(SshFixtures.Ed25519Blob(), passphrase: true)),
            ("odd", "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"));

        CheckOutcome outcome = Passphrase.Run(probes);

        Assert.AreEqual(CheckStatus.Error, outcome.Status);
        StringAssert.Contains(outcome.Summary, "odd");
    }

    [TestMethod]
    public void AnUnreadableKeyFile_IsCouldNotCheck_ButADefiniteProblemStillFails()
    {
        FakeProbes probes = Keys(("id_rsa", SshFixtures.OpenSsh(SshFixtures.RsaBlob(2048), passphrase: false)))
            .WithFileFailure(SshFixtures.Path("id_ed25519"), ProbeFailure.AccessDenied());

        Assert.AreEqual(CheckStatus.Fail, Passphrase.Run(probes).Status);

        FakeProbes onlyUnreadable = new FakeProbes().WithFileFailure(SshFixtures.Path("id_ed25519"), ProbeFailure.AccessDenied());
        Assert.AreEqual(CheckStatus.Error, Passphrase.Run(onlyUnreadable).Status);
    }

    [TestMethod]
    public void TheKeyItself_NeverAppearsInTheResult()
    {
        string key = SshFixtures.OpenSsh(SshFixtures.RsaBlob(2048), passphrase: false);
        string firstLineOfKeyData = key.Split('\n')[1];

        foreach (CheckOutcome outcome in new[] { Passphrase.Run(Keys(("id_rsa", key))), Strength.Run(Keys(("id_rsa", key))) })
        {
            string everything = outcome.Summary + string.Join('|', outcome.Findings.Select(f => f.Item + f.Found + f.Expected + f.Source));
            Assert.IsFalse(everything.Contains(firstLineOfKeyData[..16], StringComparison.Ordinal));
        }
    }

    [TestMethod]
    public void StrongKeys_Pass()
    {
        FakeProbes probes = Keys(
            ("a", SshFixtures.OpenSsh(SshFixtures.Ed25519Blob(), passphrase: true)),
            ("b", SshFixtures.OpenSsh(SshFixtures.EcdsaBlob(), passphrase: true)),
            ("c", SshFixtures.OpenSsh(SshFixtures.RsaBlob(SshKeyStrengthCheck.MinimumRsaBits), passphrase: true)));

        CheckOutcome outcome = Strength.Run(probes);

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("RSA, 2048 bits", outcome.Findings[2].Found);
    }

    [TestMethod]
    public void AShortRsaKey_Fails()
    {
        FakeProbes probes = Keys(("id_rsa", SshFixtures.OpenSsh(SshFixtures.RsaBlob(SshKeyStrengthCheck.MinimumRsaBits - 1), passphrase: true)));

        CheckOutcome outcome = Strength.Run(probes);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("id_rsa uses a weak algorithm or key size.", outcome.Summary);
        Assert.AreEqual("RSA, 2047 bits", outcome.Findings[0].Found);
    }

    [TestMethod]
    public void ADsaKey_Fails_WhateverItsSize()
    {
        FakeProbes probes = Keys(("id_dsa", SshFixtures.OpenSsh(SshFixtures.DsaBlob(3072), passphrase: true)));

        Assert.AreEqual(CheckStatus.Fail, Strength.Run(probes).Status);
    }

    [TestMethod]
    public void AnEncryptedOldStyleKey_WithoutItsPublicFile_IsCouldNotCheck()
    {
        FakeProbes probes = Keys(("id_rsa", SshFixtures.LegacyPem("RSA", passphrase: true)));

        CheckOutcome outcome = Strength.Run(probes);

        Assert.AreEqual(CheckStatus.Error, outcome.Status);
        StringAssert.Contains(outcome.Summary, ".pub");
    }

    [TestMethod]
    public void AnEncryptedOldStyleKey_WithItsPublicFile_IsJudged()
    {
        FakeProbes probes = Keys(
            ("id_rsa", SshFixtures.LegacyPem("RSA", passphrase: true)),
            ("id_rsa.pub", SshFixtures.PublicLine(SshFixtures.RsaBlob(1024))));

        Assert.AreEqual(CheckStatus.Fail, Strength.Run(probes).Status);
    }
}
