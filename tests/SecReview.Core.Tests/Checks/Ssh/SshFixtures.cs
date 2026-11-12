using System.Buffers.Binary;
using System.Text;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.Checks.Ssh;

/// <summary>
/// Key files built from made-up numbers. They have the structure of real key files, which is
/// all the checks read, but hold no key anyone ever generated.
/// </summary>
internal static class SshFixtures
{
    public const string Folder = FakeProbes.UserProfile + @"\.ssh";

    public static string Path(string name) => $@"{Folder}\{name}";

    /// <summary>A key in OpenSSH's own format.</summary>
    public static string OpenSsh(byte[] publicBlob, bool passphrase)
    {
        byte[] data =
        [
            .. "openssh-key-v1"u8, 0,
            .. SshString(passphrase ? "aes256-ctr" : "none"),
            .. SshString(passphrase ? "bcrypt" : "none"),
            .. SshString(string.Empty),
            .. UInt32(1),
            .. SshString(publicBlob),
            .. SshString(new byte[64]), // where the private half would be
        ];
        return Pem("OPENSSH PRIVATE KEY", data);
    }

    /// <summary>A key in the older PEM format: "RSA", "DSA" or "EC".</summary>
    public static string LegacyPem(string algorithm, bool passphrase, int bits = 2048)
    {
        if (passphrase)
        {
            return $"-----BEGIN {algorithm} PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00000000000000000000000000000000\n\n" +
                $"{Convert.ToBase64String(new byte[48])}\n-----END {algorithm} PRIVATE KEY-----\n";
        }

        // SEQUENCE { INTEGER 0, INTEGER <a number of the given size>, ... }
        byte[] number = Number(bits);
        byte[] body = [0x02, 0x01, 0x00, 0x02, .. DerLength(number.Length), .. number];
        return Pem($"{algorithm} PRIVATE KEY", [0x30, .. DerLength(body.Length), .. body]);
    }

    public static string Putty(byte[] publicBlob, bool passphrase)
    {
        string publicLines = Convert.ToBase64String(publicBlob, Base64FormattingOptions.InsertLineBreaks).ReplaceLineEndings("\r\n");
        int count = publicLines.Split("\r\n").Length;
        return $"PuTTY-User-Key-File-3: ssh-key\r\nEncryption: {(passphrase ? "aes256-cbc" : "none")}\r\nComment: made up\r\n" +
            $"Public-Lines: {count}\r\n{publicLines}\r\nPrivate-Lines: 1\r\nAAAA\r\n";
    }

    public static string PublicLine(byte[] publicBlob) => $"ssh-key {Convert.ToBase64String(publicBlob)} someone@example\n";

    public static byte[] RsaBlob(int bits) => [.. SshString("ssh-rsa"), .. SshString([0x01, 0x00, 0x01]), .. SshString(Number(bits))];

    public static byte[] DsaBlob(int bits = 1024) => [.. SshString("ssh-dss"), .. SshString(Number(bits))];

    public static byte[] Ed25519Blob() => [.. SshString("ssh-ed25519"), .. SshString(new byte[32])];

    public static byte[] EcdsaBlob() => [.. SshString("ecdsa-sha2-nistp256"), .. SshString("nistp256"), .. SshString(new byte[65])];

    public static byte[] SecurityKeyBlob() => [.. SshString("sk-ssh-ed25519@openssh.com"), .. SshString(new byte[32]), .. SshString("ssh:")];

    public static byte[] SshString(string text) => SshString(Encoding.ASCII.GetBytes(text));

    public static byte[] SshString(byte[] value) => [.. UInt32((uint)value.Length), .. value];

    /// <summary>A big-endian number with exactly the given number of bits, with the leading zero SSH and DER add.</summary>
    private static byte[] Number(int bits)
    {
        byte[] number = new byte[1 + ((bits + 7) / 8)];
        number[1] = (byte)(1 << ((bits - 1) % 8));
        number[^1] |= 1;
        return number;
    }

    private static byte[] UInt32(uint value)
    {
        byte[] bytes = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        return bytes;
    }

    private static byte[] DerLength(int length) => length < 0x80
        ? [(byte)length]
        : [0x82, (byte)(length >> 8), (byte)length];

    private static string Pem(string label, byte[] data) =>
        $"-----BEGIN {label}-----\n{Convert.ToBase64String(data, Base64FormattingOptions.InsertLineBreaks).ReplaceLineEndings("\n")}\n-----END {label}-----\n";
}
