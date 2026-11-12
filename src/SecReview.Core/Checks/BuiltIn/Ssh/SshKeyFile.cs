using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace SecReview.Checks.BuiltIn.Ssh;

internal enum SshKeyKind
{
    /// <summary>The kind could not be told from the file.</summary>
    Unknown = 0,
    Rsa,
    Dsa,
    Ecdsa,
    Ed25519,

    /// <summary>A key that lives on a hardware security key; the file is only a handle to it.</summary>
    SecurityKey,
}

/// <summary>What a private key file says about itself, without its secret part.</summary>
/// <param name="Kind">The algorithm.</param>
/// <param name="Bits">The key size, for RSA and DSA when it could be read.</param>
/// <param name="HasPassphrase">Whether the file is encrypted with a passphrase; null if that could not be told.</param>
internal sealed record SshKeyInfo(SshKeyKind Kind, int? Bits, bool? HasPassphrase);

/// <summary>
/// Reads the unencrypted header of a private key file: the format's own statement of whether
/// the key is encrypted, and the public half. The private half is never interpreted, and
/// nothing from the file other than the algorithm name and key size leaves this class.
/// Supports OpenSSH's own format, the older PEM formats and PuTTY's.
/// </summary>
internal static class SshKeyFile
{
    private const string OpenSshBegin = "-----BEGIN OPENSSH PRIVATE KEY-----";
    private const string PuttyPrefix = "PuTTY-User-Key-File-";
    private static readonly byte[] OpenSshMagic = [.. "openssh-key-v1"u8, 0];

    /// <summary>Whether the text is a private key in a format this class knows.</summary>
    public static bool LooksLikePrivateKey(string text)
    {
        ReadOnlySpan<char> start = text.AsSpan().TrimStart();
        return start.StartsWith(PuttyPrefix, StringComparison.Ordinal) ||
            (start.StartsWith("-----BEGIN ", StringComparison.Ordinal) && FirstLine(start).Contains("PRIVATE KEY-----", StringComparison.Ordinal));
    }

    /// <summary>
    /// What the file says about itself. <paramref name="publicKeyText"/> is the matching
    /// <c>.pub</c> file when there is one; it fills in what the private key file does not show.
    /// Returns null if the text is not a private key.
    /// </summary>
    public static SshKeyInfo? Parse(string text, string? publicKeyText)
    {
        ArgumentNullException.ThrowIfNull(text);
        if (!LooksLikePrivateKey(text))
        {
            return null;
        }

        string trimmed = text.TrimStart();
        SshKeyInfo info;
        if (trimmed.StartsWith(PuttyPrefix, StringComparison.Ordinal))
        {
            info = ParsePutty(trimmed);
        }
        else if (trimmed.StartsWith(OpenSshBegin, StringComparison.Ordinal))
        {
            info = ParseOpenSsh(trimmed);
        }
        else
        {
            info = ParsePem(trimmed);
        }

        // The public key file names the algorithm and size when the private one does not.
        if ((info.Kind == SshKeyKind.Unknown || (info.Bits is null && info.Kind is SshKeyKind.Rsa or SshKeyKind.Dsa)) &&
            publicKeyText is not null &&
            ParsePublicKeyLine(publicKeyText) is { } fromPublic &&
            (info.Kind == SshKeyKind.Unknown || info.Kind == fromPublic.Kind))
        {
            info = info with { Kind = fromPublic.Kind, Bits = fromPublic.Bits };
        }

        return info;
    }

    /// <summary>The algorithm and size from a public key line ("ssh-rsa AAAA... comment"), or null.</summary>
    internal static (SshKeyKind Kind, int? Bits)? ParsePublicKeyLine(string line)
    {
        string[] parts = line.Trim().Split((char[]?)null, 3, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2 || !TryDecodeBase64(parts[1], out byte[] blob))
        {
            return null;
        }

        return ParsePublicBlob(blob);
    }

    private static SshKeyInfo ParseOpenSsh(string text)
    {
        if (!TryDecodeBase64(PemBody(text), out byte[] data))
        {
            return new SshKeyInfo(SshKeyKind.Unknown, null, null);
        }

        try
        {
            var reader = new SshReader(data);
            if (!reader.TrySkip(OpenSshMagic) ||
                !reader.TryReadString(out ReadOnlySpan<byte> cipher) ||
                !reader.TryReadString(out ReadOnlySpan<byte> derivation) ||
                !reader.TryReadString(out _) || // key derivation options
                !reader.TryReadUInt32(out uint keys))
            {
                return new SshKeyInfo(SshKeyKind.Unknown, null, null);
            }

            // "none" with no key derivation is an unprotected key; a cipher OpenSSH knows, with
            // its key derivation, is a protected one. Anything else is not a key OpenSSH would
            // accept, and nothing is concluded from it.
            bool? hasPassphrase =
                cipher.SequenceEqual("none"u8) && derivation.SequenceEqual("none"u8) ? false
                : IsKnownCipher(cipher) && derivation.SequenceEqual("bcrypt"u8) ? true
                : null;
            if (keys < 1 || !reader.TryReadString(out ReadOnlySpan<byte> publicBlob) ||
                ParsePublicBlob(publicBlob) is not { } key)
            {
                return new SshKeyInfo(SshKeyKind.Unknown, null, hasPassphrase);
            }

            return new SshKeyInfo(key.Kind, key.Bits, hasPassphrase);
        }
        finally
        {
            // The decoded file includes the private half; it is not kept.
            CryptographicOperations.ZeroMemory(data);
        }
    }

    /// <summary>The ciphers OpenSSH can protect a private key file with.</summary>
    private static bool IsKnownCipher(ReadOnlySpan<byte> name) =>
        name.SequenceEqual("aes256-ctr"u8) || name.SequenceEqual("aes192-ctr"u8) || name.SequenceEqual("aes128-ctr"u8) ||
        name.SequenceEqual("aes256-cbc"u8) || name.SequenceEqual("aes192-cbc"u8) || name.SequenceEqual("aes128-cbc"u8) ||
        name.SequenceEqual("3des-cbc"u8) ||
        name.SequenceEqual("aes256-gcm@openssh.com"u8) || name.SequenceEqual("aes128-gcm@openssh.com"u8) ||
        name.SequenceEqual("chacha20-poly1305@openssh.com"u8);

    /// <summary>
    /// The older PEM formats. "RSA", "DSA" and "EC" files name their algorithm in the first line
    /// and are encrypted exactly when they carry a "Proc-Type: 4,ENCRYPTED" header. The newer
    /// "PRIVATE KEY" and "ENCRYPTED PRIVATE KEY" say whether they are encrypted, not what they hold.
    /// </summary>
    private static SshKeyInfo ParsePem(string text)
    {
        string first = FirstLine(text).ToString();
        string label = first["-----BEGIN ".Length..].Replace("-----", string.Empty, StringComparison.Ordinal).Trim();

        switch (label)
        {
            case "ENCRYPTED PRIVATE KEY":
                return new SshKeyInfo(SshKeyKind.Unknown, null, true);
            case "PRIVATE KEY":
                return new SshKeyInfo(SshKeyKind.Unknown, null, false);
        }

        SshKeyKind kind = label switch
        {
            "RSA PRIVATE KEY" => SshKeyKind.Rsa,
            "DSA PRIVATE KEY" => SshKeyKind.Dsa,
            "EC PRIVATE KEY" => SshKeyKind.Ecdsa,
            _ => SshKeyKind.Unknown,
        };
        if (kind == SshKeyKind.Unknown)
        {
            return new SshKeyInfo(SshKeyKind.Unknown, null, null);
        }

        bool encrypted = text.Contains("Proc-Type: 4,ENCRYPTED", StringComparison.Ordinal);
        int? bits = null;
        if (!encrypted && kind is SshKeyKind.Rsa or SshKeyKind.Dsa && TryDecodeBase64(PemBody(text), out byte[] der))
        {
            try
            {
                bits = FirstLargeIntegerBits(der);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(der);
            }
        }

        return new SshKeyInfo(kind, bits, encrypted);
    }

    /// <summary>PuTTY's format states the algorithm and the encryption in its first lines.</summary>
    private static SshKeyInfo ParsePutty(string text)
    {
        SshKeyKind kind = SshKeyKind.Unknown;
        int? bits = null;
        bool? hasPassphrase = null;

        string[] lines = text.Split('\n');
        for (int i = 0; i < lines.Length; i++)
        {
            string line = lines[i].Trim();
            if (line.StartsWith("Encryption:", StringComparison.Ordinal) && hasPassphrase is null)
            {
                // PuTTY writes exactly one of these two; anything else is not a file it would read.
                hasPassphrase = line["Encryption:".Length..].Trim() switch
                {
                    "none" => false,
                    "aes256-cbc" => true,
                    _ => null,
                };
            }
            else if (line.StartsWith("Public-Lines:", StringComparison.Ordinal) &&
                int.TryParse(line["Public-Lines:".Length..].Trim(), out int count) &&
                count is > 0 and < 200 && i + count < lines.Length)
            {
                string base64 = string.Concat(lines.Skip(i + 1).Take(count).Select(l => l.Trim()));
                if (TryDecodeBase64(base64, out byte[] blob) && ParsePublicBlob(blob) is { } key)
                {
                    (kind, bits) = key;
                }

                break;
            }
        }

        return new SshKeyInfo(kind, bits, hasPassphrase);
    }

    /// <summary>A public key in SSH wire form: the algorithm name, then its numbers.</summary>
    private static (SshKeyKind Kind, int? Bits)? ParsePublicBlob(ReadOnlySpan<byte> blob)
    {
        var reader = new SshReader(blob);
        if (!reader.TryReadString(out ReadOnlySpan<byte> nameBytes))
        {
            return null;
        }

        string name = Encoding.ASCII.GetString(nameBytes);
        if (name.StartsWith("sk-", StringComparison.Ordinal))
        {
            return (SshKeyKind.SecurityKey, null);
        }

        if (name == "ssh-ed25519")
        {
            return (SshKeyKind.Ed25519, null);
        }

        if (name.StartsWith("ecdsa-sha2-", StringComparison.Ordinal))
        {
            return (SshKeyKind.Ecdsa, null);
        }

        if (name == "ssh-rsa")
        {
            // Exponent, then modulus; the modulus is the key size.
            return reader.TryReadString(out _) && reader.TryReadString(out ReadOnlySpan<byte> modulus)
                ? (SshKeyKind.Rsa, BitLength(modulus))
                : (SshKeyKind.Rsa, null);
        }

        if (name == "ssh-dss")
        {
            return reader.TryReadString(out ReadOnlySpan<byte> prime)
                ? (SshKeyKind.Dsa, BitLength(prime))
                : (SshKeyKind.Dsa, null);
        }

        return (SshKeyKind.Unknown, null);
    }

    /// <summary>
    /// The size of the first large number in an unencrypted RSA or DSA key in DER form, which
    /// is the modulus or prime. Only lengths are read, never the numbers themselves.
    /// </summary>
    private static int? FirstLargeIntegerBits(ReadOnlySpan<byte> der)
    {
        int position = 0;
        if (!TryReadDerHeader(der, ref position, out byte tag, out _) || tag != 0x30)
        {
            return null;
        }

        // The version, then the number wanted.
        for (int i = 0; i < 2; i++)
        {
            if (!TryReadDerHeader(der, ref position, out tag, out int length) || tag != 0x02 || length > der.Length - position)
            {
                return null;
            }

            if (i == 1)
            {
                return BitLength(der.Slice(position, length));
            }

            position += length;
        }

        return null;
    }

    private static bool TryReadDerHeader(ReadOnlySpan<byte> der, ref int position, out byte tag, out int length)
    {
        tag = 0;
        length = 0;
        if (position + 2 > der.Length)
        {
            return false;
        }

        tag = der[position++];
        int first = der[position++];
        if (first < 0x80)
        {
            length = first;
            return true;
        }

        int count = first & 0x7F;
        if (count is 0 or > 3 || position + count > der.Length)
        {
            return false;
        }

        for (int i = 0; i < count; i++)
        {
            length = (length << 8) | der[position++];
        }

        return true;
    }

    /// <summary>The number of significant bits in a big-endian number.</summary>
    private static int? BitLength(ReadOnlySpan<byte> number)
    {
        int start = number.IndexOfAnyExcept((byte)0);
        if (start < 0)
        {
            return null;
        }

        return ((number.Length - start - 1) * 8) + (8 - byte.LeadingZeroCount(number[start]));
    }

    /// <summary>The base64 between the BEGIN and END lines, without any "Name: value" headers.</summary>
    private static string PemBody(string text)
    {
        var body = new StringBuilder();
        foreach (string raw in text.Split('\n').Skip(1))
        {
            string line = raw.Trim();
            if (line.StartsWith("-----END", StringComparison.Ordinal))
            {
                break;
            }

            if (line.Length > 0 && !line.Contains(':', StringComparison.Ordinal))
            {
                body.Append(line);
            }
        }

        return body.ToString();
    }

    private static ReadOnlySpan<char> FirstLine(ReadOnlySpan<char> text)
    {
        int end = text.IndexOfAny('\r', '\n');
        return end < 0 ? text : text[..end];
    }

    private static bool TryDecodeBase64(string base64, out byte[] data)
    {
        data = new byte[(base64.Length / 4 * 3) + 3];
        if (Convert.TryFromBase64String(base64, data, out int written))
        {
            Array.Resize(ref data, written);
            return true;
        }

        data = [];
        return false;
    }

    /// <summary>Reads SSH wire values (length-prefixed strings, big-endian numbers) without ever reading past the end.</summary>
    private ref struct SshReader(ReadOnlySpan<byte> data)
    {
        private ReadOnlySpan<byte> _rest = data;

        public bool TrySkip(ReadOnlySpan<byte> expected)
        {
            if (!_rest.StartsWith(expected))
            {
                return false;
            }

            _rest = _rest[expected.Length..];
            return true;
        }

        public bool TryReadUInt32(out uint value)
        {
            if (!BinaryPrimitives.TryReadUInt32BigEndian(_rest, out value))
            {
                return false;
            }

            _rest = _rest[4..];
            return true;
        }

        public bool TryReadString(out ReadOnlySpan<byte> value)
        {
            value = default;
            if (!TryReadUInt32(out uint length) || length > (uint)_rest.Length)
            {
                return false;
            }

            value = _rest[..(int)length];
            _rest = _rest[(int)length..];
            return true;
        }
    }
}
