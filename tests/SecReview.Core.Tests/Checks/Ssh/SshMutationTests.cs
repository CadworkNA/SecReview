using System.Text;
using SecReview.Checks;
using SecReview.Checks.BuiltIn.Ssh;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.Checks.Ssh;

/// <summary>
/// Damaged input, thousands of times over with a fixed seed: the readers must never throw or
/// hang, and damage must never turn an unprotected or weak key into a protected or strong one.
/// </summary>
[TestClass]
public sealed class SshMutationTests
{
    private const int Rounds = 3000;

    private static IEnumerable<(string Name, string Text)> UnprotectedKeys() =>
    [
        ("openssh-rsa", SshFixtures.OpenSsh(SshFixtures.RsaBlob(2048), passphrase: false)),
        ("openssh-ed25519", SshFixtures.OpenSsh(SshFixtures.Ed25519Blob(), passphrase: false)),
        ("pem-rsa", SshFixtures.LegacyPem("RSA", passphrase: false)),
        ("pem-ec", SshFixtures.LegacyPem("EC", passphrase: false)),
        ("putty", SshFixtures.Putty(SshFixtures.RsaBlob(2048), passphrase: false)),
    ];

    private static IEnumerable<(string Name, string Text)> WeakKeys() =>
    [
        ("openssh-rsa-1024", SshFixtures.OpenSsh(SshFixtures.RsaBlob(1024), passphrase: true)),
        ("openssh-dsa", SshFixtures.OpenSsh(SshFixtures.DsaBlob(), passphrase: true)),
        ("pem-rsa-1024", SshFixtures.LegacyPem("RSA", passphrase: false, bits: 1024)),
        ("putty-rsa-1024", SshFixtures.Putty(SshFixtures.RsaBlob(1024), passphrase: true)),
    ];

    [TestMethod]
    public void DamagedKeyFiles_NeverThrow_AndNeverGainAPassphrase()
    {
        foreach ((string name, string text) in UnprotectedKeys())
        {
            var random = new Random(20261111);
            for (int round = 0; round < Rounds; round++)
            {
                string damaged = Damage(text, random);

                SshKeyInfo? info = SshKeyFile.Parse(damaged, publicKeyText: null);

                Assert.IsFalse(info?.HasPassphrase == true, $"{name}, round {round}: damage made the key look protected");
            }
        }
    }

    [TestMethod]
    public void DamagedKeyFiles_NeverMakeAWeakKeyLookStrong()
    {
        foreach ((string name, string text) in WeakKeys())
        {
            var random = new Random(20261111);
            for (int round = 0; round < Rounds; round++)
            {
                string damaged = Damage(text, random);

                SshKeyInfo? info = SshKeyFile.Parse(damaged, publicKeyText: null);

                bool strong = info is not null && (info.Kind is SshKeyKind.Ed25519 or SshKeyKind.Ecdsa or SshKeyKind.SecurityKey ||
                    (info.Kind == SshKeyKind.Rsa && info.Bits >= SshKeyStrengthCheck.MinimumRsaBits));
                Assert.IsFalse(strong, $"{name}, round {round}: damage made the key look strong");
            }
        }
    }

    [TestMethod]
    public void DamagedPublicKeyLines_NeverThrow()
    {
        string line = SshFixtures.PublicLine(SshFixtures.RsaBlob(2048));
        var random = new Random(20261111);
        for (int round = 0; round < Rounds; round++)
        {
            _ = SshKeyFile.ParsePublicKeyLine(Damage(line, random));
        }
    }

    [TestMethod]
    public void DamagedSettingsFiles_AlwaysEndWithAnAnswer()
    {
        const string Config =
            "# hosts\nInclude conf.d/*.conf ~/.ssh/extra\nHost *\n  ForwardAgent yes\n  StrictHostKeyChecking \"no\"\n" +
            "Match host build-* user dev\n  UserKnownHostsFile=/dev/null\nHost a b !c\n\tIdentityFile \"C:\\my keys\\id\"\n";
        var check = new SshConfigCheck();
        var random = new Random(20261111);

        for (int round = 0; round < Rounds; round++)
        {
            FakeProbes probes = new FakeProbes()
                .WithFile(SshFixtures.Path("config"), Damage(Config, random))
                .WithFile(SshFixtures.Path("extra"), Damage("Include config\nForwardAgent no\n", random))
                .WithFile(SshFixtures.Path(@"conf.d\a.conf"), Damage("Host x\n  ForwardAgent yes\n", random));

            CheckOutcome outcome = check.Run(probes);

            Assert.IsTrue(Enum.IsDefined(outcome.Status), $"round {round}");
            Assert.IsFalse(string.IsNullOrWhiteSpace(outcome.Summary), $"round {round}");
        }
    }

    /// <summary>
    /// One to three random changes: a character replaced, removed, inserted or doubled, the text
    /// cut short, or (for base64 bodies) one byte of the decoded data changed.
    /// </summary>
    private static string Damage(string text, Random random)
    {
        var damaged = new StringBuilder(text);
        int changes = random.Next(1, 4);
        for (int i = 0; i < changes && damaged.Length > 0; i++)
        {
            int at = random.Next(damaged.Length);
            switch (random.Next(6))
            {
                case 0:
                    damaged[at] = (char)random.Next(32, 127);
                    break;
                case 1:
                    damaged.Remove(at, 1);
                    break;
                case 2:
                    damaged.Insert(at, (char)random.Next(9, 127));
                    break;
                case 3:
                    damaged.Length = at;
                    break;
                case 4:
                    damaged.Insert(at, damaged.ToString(at, Math.Min(random.Next(1, 40), damaged.Length - at)));
                    break;
                default:
                    FlipDecodedByte(damaged, random);
                    break;
            }
        }

        return damaged.ToString();
    }

    /// <summary>Changes one byte inside the longest base64 line, keeping it valid base64.</summary>
    private static void FlipDecodedByte(StringBuilder text, Random random)
    {
        string[] lines = text.ToString().Split('\n');
        int longest = Array.IndexOf(lines, lines.MaxBy(l => l.Length));
        byte[] bytes = new byte[lines[longest].Length];
        if (lines[longest].Trim().Length < 8 || !Convert.TryFromBase64String(lines[longest].Trim(), bytes, out int written) || written == 0)
        {
            return;
        }

        bytes[random.Next(written)] ^= (byte)(1 << random.Next(8));
        lines[longest] = Convert.ToBase64String(bytes, 0, written);
        text.Clear().Append(string.Join('\n', lines));
    }
}
