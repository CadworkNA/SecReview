using SecReview.Checks.BuiltIn.Ssh;

namespace SecReview.Tests.Checks.Ssh;

[TestClass]
public sealed class SshKeyFileTests
{
    [TestMethod]
    [DataRow(true)]
    [DataRow(false)]
    public void OpenSsh_SaysWhetherThereIsAPassphrase_AndWhatTheKeyIs(bool passphrase)
    {
        SshKeyInfo? info = SshKeyFile.Parse(SshFixtures.OpenSsh(SshFixtures.RsaBlob(3072), passphrase), publicKeyText: null);

        Assert.AreEqual(new SshKeyInfo(SshKeyKind.Rsa, 3072, passphrase), info);
    }

    [TestMethod]
    public void OpenSsh_KnowsEachAlgorithm()
    {
        Assert.AreEqual(SshKeyKind.Ed25519, SshKeyFile.Parse(SshFixtures.OpenSsh(SshFixtures.Ed25519Blob(), true), null)!.Kind);
        Assert.AreEqual(SshKeyKind.Ecdsa, SshKeyFile.Parse(SshFixtures.OpenSsh(SshFixtures.EcdsaBlob(), true), null)!.Kind);
        Assert.AreEqual(SshKeyKind.SecurityKey, SshKeyFile.Parse(SshFixtures.OpenSsh(SshFixtures.SecurityKeyBlob(), false), null)!.Kind);
        Assert.AreEqual(
            new SshKeyInfo(SshKeyKind.Dsa, 1024, false), SshKeyFile.Parse(SshFixtures.OpenSsh(SshFixtures.DsaBlob(), false), null));
    }

    [TestMethod]
    [DataRow(1024)]
    [DataRow(2047)]
    [DataRow(2048)]
    [DataRow(4096)]
    public void RsaSize_IsCountedInBits_NotBytes(int bits)
    {
        Assert.AreEqual(bits, SshKeyFile.Parse(SshFixtures.OpenSsh(SshFixtures.RsaBlob(bits), false), null)!.Bits);
        Assert.AreEqual(bits, SshKeyFile.Parse(SshFixtures.LegacyPem("RSA", passphrase: false, bits), null)!.Bits);
    }

    [TestMethod]
    public void LegacyPem_EncryptedHeader_MeansPassphrase_AndHidesTheSize()
    {
        Assert.AreEqual(
            new SshKeyInfo(SshKeyKind.Rsa, null, true), SshKeyFile.Parse(SshFixtures.LegacyPem("RSA", passphrase: true), null));
        Assert.AreEqual(
            new SshKeyInfo(SshKeyKind.Ecdsa, null, false), SshKeyFile.Parse(SshFixtures.LegacyPem("EC", passphrase: false), null));
        Assert.AreEqual(SshKeyKind.Dsa, SshKeyFile.Parse(SshFixtures.LegacyPem("DSA", passphrase: true), null)!.Kind);
    }

    [TestMethod]
    public void ThePublicKeyFile_FillsInWhatAnEncryptedKeyHides()
    {
        string publicKey = SshFixtures.PublicLine(SshFixtures.RsaBlob(1024));

        Assert.AreEqual(
            new SshKeyInfo(SshKeyKind.Rsa, 1024, true), SshKeyFile.Parse(SshFixtures.LegacyPem("RSA", passphrase: true), publicKey));
    }

    [TestMethod]
    public void ThePublicKeyFile_OfAnotherAlgorithm_IsNotBelieved()
    {
        string publicKey = SshFixtures.PublicLine(SshFixtures.Ed25519Blob());

        Assert.AreEqual(
            new SshKeyInfo(SshKeyKind.Rsa, null, true), SshKeyFile.Parse(SshFixtures.LegacyPem("RSA", passphrase: true), publicKey));
    }

    [TestMethod]
    public void Pkcs8_SaysOnlyWhetherItIsEncrypted()
    {
        Assert.AreEqual(
            new SshKeyInfo(SshKeyKind.Unknown, null, true),
            SshKeyFile.Parse("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n", null));
        Assert.AreEqual(
            new SshKeyInfo(SshKeyKind.Ed25519, null, false),
            SshKeyFile.Parse(
                "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", SshFixtures.PublicLine(SshFixtures.Ed25519Blob())));
    }

    [TestMethod]
    [DataRow(true)]
    [DataRow(false)]
    public void Putty_SaysWhetherThereIsAPassphrase_AndWhatTheKeyIs(bool passphrase)
    {
        Assert.AreEqual(
            new SshKeyInfo(SshKeyKind.Rsa, 2048, passphrase),
            SshKeyFile.Parse(SshFixtures.Putty(SshFixtures.RsaBlob(2048), passphrase), null));
    }

    [TestMethod]
    [DataRow("")]
    [DataRow("ssh-ed25519 AAAA someone@example")]
    [DataRow("Host *\n  ForwardAgent no\n")]
    [DataRow("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")]
    public void WhatIsNotAPrivateKey_IsNotOne(string text)
    {
        Assert.IsFalse(SshKeyFile.LooksLikePrivateKey(text));
        Assert.IsNull(SshKeyFile.Parse(text, null));
    }

    [TestMethod]
    [DataRow("-----BEGIN OPENSSH PRIVATE KEY-----\n!!!not base64!!!\n-----END OPENSSH PRIVATE KEY-----\n")]
    [DataRow("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n")]
    [DataRow("-----BEGIN OPENSSH PRIVATE KEY-----")]
    [DataRow("-----BEGIN SOMETHING PRIVATE KEY-----\nAAAA\n")]
    [DataRow("PuTTY-User-Key-File-3: ssh-key\nPublic-Lines: 99999\n")]
    public void ADamagedKeyFile_IsUnknown_NeverAnException_AndNeverAPass(string text)
    {
        SshKeyInfo? info = SshKeyFile.Parse(text, null);

        Assert.IsNotNull(info);
        Assert.AreEqual(SshKeyKind.Unknown, info.Kind);
        Assert.IsNull(info.HasPassphrase);
    }

    [TestMethod]
    public void ATruncatedOpenSshKey_KeepsWhatItStated_AndDoesNotReadPastTheEnd()
    {
        string whole = SshFixtures.OpenSsh(SshFixtures.RsaBlob(2048), passphrase: false);
        string[] lines = whole.Split('\n');

        // Only the first line of base64: the header survives, the public key does not.
        SshKeyInfo? info = SshKeyFile.Parse($"{lines[0]}\n{lines[1]}\n", null);

        Assert.IsNotNull(info);
        Assert.AreEqual(SshKeyKind.Unknown, info.Kind);
    }
}
