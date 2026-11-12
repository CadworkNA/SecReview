using SecReview.Probing;

namespace SecReview.Checks.BuiltIn.Ssh;

/// <summary>One private key file found in the user's <c>.ssh</c> folder.</summary>
/// <param name="FileName">The file's name, without the folder.</param>
/// <param name="Info">What the file says about itself; null if it could not be read.</param>
/// <param name="Unreadable">Why the file could not be read, when it could not.</param>
/// <param name="HasPublicFile">Whether a readable <c>.pub</c> file sits next to it.</param>
internal sealed record SshKeyOnDisk(string FileName, SshKeyInfo? Info, string? Unreadable, bool HasPublicFile = false);

/// <summary>Finds the private keys in the signed-in user's <c>.ssh</c> folder.</summary>
internal static class SshKeys
{
    /// <summary>A private key is a few kilobytes at most; larger files are not keys.</summary>
    private const int MaximumKeyBytes = 64 * 1024;

    /// <summary>Files in <c>.ssh</c> that are never private keys.</summary>
    private static readonly string[] NotKeys = ["config", "known_hosts", "known_hosts.old", "authorized_keys", "environment", "rc"];

    /// <summary>The <c>.ssh</c> folder of the signed-in user.</summary>
    public static ProbeResult<string> Folder(SystemProbes probes)
    {
        ProbeResult<string> profile = probes.Environment.Folder(KnownFolder.UserProfile);
        return profile.IsOk ? ProbeResult<string>.Ok(profile.Value + @"\.ssh") : profile;
    }

    /// <summary>
    /// The private keys in the folder. An empty list when there is no such folder or it holds
    /// no keys; a failure when the folder is there but cannot be listed.
    /// </summary>
    public static ProbeResult<IReadOnlyList<SshKeyOnDisk>> Find(SystemProbes probes)
    {
        ProbeResult<string> folder = Folder(probes);
        if (!folder.IsOk)
        {
            return folder.ToFailure();
        }

        ProbeResult<IReadOnlyList<FileEntry>> entries = probes.Files.List(folder.Value!);
        if (entries.Status == ProbeStatus.NotFound)
        {
            return ProbeResult<IReadOnlyList<SshKeyOnDisk>>.Ok([]);
        }

        if (!entries.IsOk)
        {
            return entries.ToFailure();
        }

        var keys = new List<SshKeyOnDisk>();
        foreach (FileEntry entry in entries.Value!)
        {
            // The size of a link is not the size of the file it points to, so a link is read to find out.
            if (entry.IsDirectory || (!entry.IsLink && entry.Length is 0 or > MaximumKeyBytes) ||
                entry.Name.EndsWith(".pub", StringComparison.OrdinalIgnoreCase) ||
                NotKeys.Contains(entry.Name, StringComparer.OrdinalIgnoreCase))
            {
                continue;
            }

            string path = $@"{folder.Value}\{entry.Name}";
            ProbeResult<string> text = probes.Files.ReadText(path, MaximumKeyBytes);
            if (text.Status == ProbeStatus.NotFound || text.Detail == IFileProbe.NotTextDetail ||
                text.Detail?.StartsWith(IFileProbe.TooLargeDetailStart, StringComparison.Ordinal) == true)
            {
                // Gone since it was listed, not text, or far larger than any key: not a key file.
                continue;
            }

            if (!text.IsOk)
            {
                // It may be a key, and nothing can be said about it: reported, never skipped.
                keys.Add(new SshKeyOnDisk(
                    entry.Name,
                    null,
                    text.Status == ProbeStatus.AccessDenied ? "Access denied" : text.Detail ?? "Could not be read"));
                continue;
            }

            if (!SshKeyFile.LooksLikePrivateKey(text.Value!))
            {
                continue;
            }

            ProbeResult<string> publicKey = probes.Files.ReadText(path + ".pub", MaximumKeyBytes);
            keys.Add(new SshKeyOnDisk(
                entry.Name, SshKeyFile.Parse(text.Value!, publicKey.IsOk ? publicKey.Value : null), null, publicKey.IsOk));
        }

        return ProbeResult<IReadOnlyList<SshKeyOnDisk>>.Ok(keys);
    }

    /// <summary>The algorithm and size in words: "RSA, 2048 bits".</summary>
    public static string Describe(SshKeyInfo info) => info.Kind switch
    {
        SshKeyKind.Rsa => info.Bits is { } bits ? $"RSA, {bits} bits" : "RSA",
        SshKeyKind.Dsa => "DSA",
        SshKeyKind.Ecdsa => "ECDSA",
        SshKeyKind.Ed25519 => "Ed25519",
        SshKeyKind.SecurityKey => "Hardware security key",
        _ => "Unknown kind",
    };
}
