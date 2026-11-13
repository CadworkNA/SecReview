using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SecReview.Checks;
using SecReview.Probing;
using SecReview.SupplyChain;
using SecReview.SupplyChain.Trust;
using SecReview.Tests.Checks;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.SupplyChain;

/// <summary>
/// Trusted certificate authorities whose key is on the PC. The certificates are made here,
/// for made-up names; none comes from a real PC and no certificate store is touched.
/// </summary>
[TestClass]
public sealed class RootKeysCheckTests
{
    private const string MachineRoots = @"SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates";

    private static readonly string PersonalFolder =
        FakeProbes.FolderPath(KnownFolder.RoamingAppData) + @"\" + RootKeysCheck.UserPersonalFolder;

    private static readonly string LocalAuthorityFolder = FakeProbes.FolderPath(KnownFolder.LocalAppData) + @"\mkcert";

    private static readonly Made Authority = Make("Example Debugging Authority", authority: true);
    private static readonly Made OneSite = Make("localhost", authority: false);
    private static readonly Made Unmarked = Make("Example Old Authority", authority: null);

    private static readonly RootKeysCheck Check = new();

    private sealed record Made(byte[] Certificate, string Thumbprint, string Pem);

    private static Made Make(string name, bool? authority)
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={name}", key, HashAlgorithmName.SHA256);
        if (authority is { } marked)
        {
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(marked, false, 0, true));
        }

        using X509Certificate2 certificate = request.CreateSelfSigned(CheckTesting.Now.AddDays(-1), CheckTesting.Now.AddDays(30));
        return new Made(certificate.RawData, certificate.Thumbprint.ToUpperInvariant(), certificate.ExportCertificatePem());
    }

    /// <summary>A certificate as a store keeps it: a few properties, one of them the certificate.</summary>
    private static byte[] Stored(Made made, bool withKey = false)
    {
        var bytes = new List<byte>();
        if (withKey)
        {
            Property(bytes, StoredCertificate.KeyProperty, [1, 2, 3, 4]);
        }

        Property(bytes, 3, new byte[20]);
        Property(bytes, StoredCertificate.CertificateProperty, made.Certificate);
        return [.. bytes];

        static void Property(List<byte> to, uint id, byte[] data)
        {
            to.AddRange(BitConverter.GetBytes(id));
            to.AddRange(BitConverter.GetBytes(1u));
            to.AddRange(BitConverter.GetBytes((uint)data.Length));
            to.AddRange(data);
        }
    }

    private static FakeProbes Trust(FakeProbes probes, Made made, RegistryRoot root = RegistryRoot.CurrentUser) => probes.WithRegistryValue(
        root,
        $@"{(root == RegistryRoot.CurrentUser ? RootCertificatesCheck.UserRoots : MachineRoots)}\{made.Thumbprint}",
        "Blob",
        RegistryValue.FromBinary(Stored(made)));

    private static FakeProbes MachinePersonal(FakeProbes probes, Made made, bool withKey = true) => probes.WithRegistryValue(
        RegistryRoot.LocalMachine, $@"{RootKeysCheck.MachinePersonal}\{made.Thumbprint}", "Blob", RegistryValue.FromBinary(Stored(made, withKey)));

    private static FakeProbes UserPersonal(FakeProbes probes, Made made) => probes.WithFile($@"{PersonalFolder}\{made.Thumbprint}", "not text on a real PC");

    private static FakeProbes LocalAuthority(FakeProbes probes, Made made, string? folder = null) => probes
        .WithFile($@"{folder ?? LocalAuthorityFolder}\{RootKeysCheck.AuthorityFile}", made.Pem)
        .WithFile($@"{folder ?? LocalAuthorityFolder}\{RootKeysCheck.KeyFile}", "made-up key text");

    private static string Everything(CheckOutcome outcome) =>
        outcome.Summary + string.Join('|', outcome.Findings.Select(f => f.Item + f.Found + f.Expected + f.Source));

    [TestMethod]
    public void WithNothingTrustedThatHasAKeyHere_ItPasses()
    {
        CheckOutcome nothing = Check.Run(new FakeProbes());
        CheckOutcome trustedOnly = Check.Run(Trust(new FakeProbes(), Authority));
        CheckOutcome ownOnly = Check.Run(UserPersonal(MachinePersonal(new FakeProbes(), Authority), OneSite));

        Assert.AreEqual(CheckStatus.Pass, nothing.Status);
        Assert.AreEqual("No trusted certificate authority has its private key on this PC.", nothing.Summary);
        Assert.AreEqual(CheckStatus.Pass, trustedOnly.Status);
        Assert.AreEqual(CheckStatus.Pass, ownOnly.Status, "a certificate with a key that is not a trusted authority is an ordinary one");
        Assert.AreEqual(CheckScope.User, Check.Definition.Scope);
    }

    [TestMethod]
    [DataRow(RegistryRoot.CurrentUser)]
    [DataRow(RegistryRoot.LocalMachine)]
    public void ATrustedAuthorityWithItsKeyInThePcsPersonalStore_Fails_ByThumbprint(RegistryRoot trustedFor)
    {
        CheckOutcome outcome = Check.Run(MachinePersonal(Trust(new FakeProbes(), Authority, trustedFor), Authority));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("1 trusted certificate authority has its private key on this PC.", outcome.Summary);
        Assert.AreEqual(
            $"Trusted certificate authority: Thumbprint {Authority.Thumbprint}, with a private key in the personal certificates (expected Its key kept off this PC) [problem]",
            outcome.Rows()[0]);
        Assert.AreEqual($@"HKLM\{RootKeysCheck.MachinePersonal}", outcome.Findings[0].Source);
        Assert.IsFalse(Everything(outcome).Contains("Example Debugging", StringComparison.Ordinal), "only the thumbprint is shown");
    }

    [TestMethod]
    public void ACopyInThePersonalStoreWithoutAKey_Passes()
    {
        FakeProbes probes = MachinePersonal(Trust(new FakeProbes(), Authority), Authority, withKey: false);

        Assert.AreEqual(CheckStatus.Pass, Check.Run(probes).Status);
    }

    [TestMethod]
    public void ATrustedAuthorityAmongTheUsersPersonalCertificates_Fails_SayingWhatWasSeen()
    {
        CheckOutcome outcome = Check.Run(UserPersonal(Trust(new FakeProbes(), Authority, RegistryRoot.LocalMachine), Authority));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        StringAssert.Contains(outcome.Findings[0].Found, "also in your personal certificates");
        Assert.AreEqual(PersonalFolder, outcome.Findings[0].Source);
    }

    [TestMethod]
    public void ATrustedCertificateForOneSite_IsListed_NotFailed()
    {
        CheckOutcome outcome = Check.Run(UserPersonal(Trust(new FakeProbes(), OneSite), OneSite));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        StringAssert.StartsWith(outcome.Rows()[^1], $"Trusted certificate for one site: Thumbprint {OneSite.Thumbprint}");
        StringAssert.EndsWith(outcome.Rows()[^1], "[note]");
    }

    [TestMethod]
    public void ATrustedCertificateThatDoesNotSayWhatItIs_CountsAsAnAuthority()
    {
        Assert.AreEqual(CheckStatus.Fail, Check.Run(MachinePersonal(Trust(new FakeProbes(), Unmarked), Unmarked)).Status);
    }

    [TestMethod]
    public void SeenInTwoPlaces_ItIsOneRow_AndSeveralAreCounted()
    {
        FakeProbes twice = UserPersonal(MachinePersonal(Trust(new FakeProbes(), Authority), Authority), Authority);
        FakeProbes two = MachinePersonal(MachinePersonal(Trust(Trust(new FakeProbes(), Authority), Unmarked), Authority), Unmarked);

        Assert.AreEqual(1, Check.Run(twice).Findings.Count);
        Assert.AreEqual("2 trusted certificate authorities have their private key on this PC.", Check.Run(two).Summary);
    }

    [TestMethod]
    public void ALocalAuthorityWithItsKeyFileBesideIt_Fails_WhenItIsTrusted()
    {
        CheckOutcome trusted = Check.Run(LocalAuthority(Trust(new FakeProbes(), Authority), Authority));
        CheckOutcome notTrusted = Check.Run(LocalAuthority(new FakeProbes(), Authority));
        CheckOutcome withoutKey = Check.Run(
            Trust(new FakeProbes(), Authority).WithFile($@"{LocalAuthorityFolder}\{RootKeysCheck.AuthorityFile}", Authority.Pem));

        Assert.AreEqual(CheckStatus.Fail, trusted.Status);
        Assert.AreEqual($"Thumbprint {Authority.Thumbprint}, with its private key in a file", trusted.Findings[0].Found);
        Assert.AreEqual($@"{LocalAuthorityFolder}\{RootKeysCheck.KeyFile}", trusted.Findings[0].Source);
        Assert.IsFalse(Everything(trusted).Contains("made-up key text", StringComparison.Ordinal));
        Assert.AreEqual(CheckStatus.Pass, notTrusted.Status);
        Assert.AreEqual(CheckStatus.Pass, withoutKey.Status);
    }

    [TestMethod]
    public void TheLocalAuthoritysFolderCanBeMoved_AndAnUnreadableCertificateIsCouldNotCheck()
    {
        const string Moved = @"D:\Tools\authority";
        FakeProbes moved = LocalAuthority(Trust(new FakeProbes(), Authority), Authority, Moved)
            .WithRegistryValue(RegistryRoot.CurrentUser, PersistentEnvironment.UserKey, "CAROOT", RegistryValue.FromText(Moved));
        FakeProbes broken = Trust(new FakeProbes(), Authority)
            .WithFile($@"{LocalAuthorityFolder}\{RootKeysCheck.AuthorityFile}", "-----BEGIN CERTIFICATE-----\nnot one\n-----END CERTIFICATE-----")
            .WithFile($@"{LocalAuthorityFolder}\{RootKeysCheck.KeyFile}", "made-up key text");

        Assert.AreEqual(CheckStatus.Fail, Check.Run(moved).Status);
        Assert.AreEqual(CheckStatus.Error, Check.Run(broken).Status);
    }

    [TestMethod]
    public void AStoredCertificateThatCannotBeRead_IsCouldNotCheck_NeverAPass()
    {
        FakeProbes damagedRoot = MachinePersonal(new FakeProbes(), Authority).WithRegistryValue(
            RegistryRoot.CurrentUser, $@"{RootCertificatesCheck.UserRoots}\{Authority.Thumbprint}", "Blob", RegistryValue.FromBinary([1, 2, 3]));
        FakeProbes damagedCopy = Trust(new FakeProbes(), Authority).WithRegistryValue(
            RegistryRoot.LocalMachine, $@"{RootKeysCheck.MachinePersonal}\{Authority.Thumbprint}", "Blob", RegistryValue.FromBinary([1, 2, 3]));

        Assert.AreEqual(CheckStatus.Error, Check.Run(damagedRoot).Status);
        Assert.AreEqual(CheckStatus.Error, Check.Run(damagedCopy).Status);
    }

    [TestMethod]
    public void WhenAStoreCannotBeRead_TheAnswerIsCouldNotCheck()
    {
        var registry = new FakeProbes { RegistryFailure = ProbeFailure.Failed("The registry did not answer.") };
        FakeProbes folder = Trust(new FakeProbes(), Authority).WithFolderFailure(PersonalFolder, ProbeFailure.Failed("The folder did not answer."));

        Assert.AreEqual(CheckStatus.Error, Check.Run(registry).Status);
        Assert.AreEqual(CheckStatus.Error, Check.Run(folder).Status);
    }

    [TestMethod]
    public void StoredCertificate_ReadsItsProperties_AndRefusesWhatIsNotOne()
    {
        Assert.IsTrue(StoredCertificate.TryRead(Stored(Authority, withKey: true), out ReadOnlySpan<byte> certificate, out bool hasKey));
        Assert.IsTrue(hasKey);
        Assert.IsTrue(certificate.SequenceEqual(Authority.Certificate));
        Assert.IsTrue(StoredCertificate.TryRead(Stored(Authority), out _, out hasKey));
        Assert.IsFalse(hasKey);

        byte[] whole = Stored(Authority, withKey: true);
        Assert.IsFalse(StoredCertificate.TryRead([], out _, out _));
        Assert.IsFalse(StoredCertificate.TryRead(whole.AsSpan(0, whole.Length - 1), out _, out _), "cut short");
        Assert.IsFalse(StoredCertificate.TryRead([.. whole, 0], out _, out _), "something after the last property");
        Assert.IsFalse(StoredCertificate.TryRead([2, 0, 0, 0, 1, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF], out _, out _), "a length past the end");

        Assert.AreEqual(true, StoredCertificate.IsAuthority(Authority.Certificate));
        Assert.AreEqual(false, StoredCertificate.IsAuthority(OneSite.Certificate));
        Assert.AreEqual(true, StoredCertificate.IsAuthority(Unmarked.Certificate));
        Assert.IsNull(StoredCertificate.IsAuthority([0x30, 0x03, 1, 2, 3]));
        Assert.AreEqual(Authority.Thumbprint, StoredCertificate.ThumbprintOfPem(Authority.Pem));
        Assert.IsNull(StoredCertificate.ThumbprintOfPem("no certificate here"));
    }

    [TestMethod]
    public void StoredCertificate_OnDamagedBytes_NeverThrows()
    {
        byte[] whole = Stored(Authority, withKey: true);
        var random = new Random(20261113);
        for (int round = 0; round < 2000; round++)
        {
            byte[] damaged = [.. whole];
            for (int change = random.Next(1, 4); change > 0; change--)
            {
                damaged[random.Next(damaged.Length)] = (byte)random.Next(256);
            }

            if (StoredCertificate.TryRead(damaged.AsSpan(0, random.Next(damaged.Length + 1)), out ReadOnlySpan<byte> certificate, out _))
            {
                _ = StoredCertificate.IsAuthority(certificate);
            }
        }
    }
}
