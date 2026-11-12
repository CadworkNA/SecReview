using System.Text;

namespace SecReview.Probing.Windows;

/// <summary>Reads files and folders from disk, read-only.</summary>
public sealed class DiskFileProbe : IFileProbe
{
    /// <summary>A folder with more entries than this is not listed: nothing a check reads is that large.</summary>
    public const int MaximumEntries = 20_000;

    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    public ProbeResult<string> ReadText(string path, int maximumBytes = IFileProbe.DefaultMaximumBytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumBytes);
        if (!IsFullPath(path))
        {
            return ProbeFailure.Failed("The file's location is not a path on this PC.");
        }

        try
        {
            // Others may keep writing, renaming or deleting the file: reading must not get in the way.
            using var stream = new FileStream(
                path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, bufferSize: 4096);

            // One byte more than allowed shows that a file is too large even if its size is
            // not reported or changes while it is read. A small file gets a small buffer.
            long reported = stream.CanSeek ? stream.Length : maximumBytes;
            byte[] buffer = new byte[(int)Math.Min(reported, maximumBytes) + 1];
            int read = stream.ReadAtLeast(buffer, buffer.Length, throwOnEndOfStream: false);
            if (read == buffer.Length && read <= maximumBytes && stream.ReadByte() >= 0)
            {
                // The file grew past its reported size while it was read; what was read is not all of it.
                return ProbeFailure.Failed("The file changed while it was being read.");
            }

            if (read > maximumBytes)
            {
                return ProbeFailure.Failed($"{IFileProbe.TooLargeDetailStart} {maximumBytes / 1024} KB and was not read.");
            }

            return Decode(buffer.AsSpan(0, read));
        }
#pragma warning disable CA1031 // A probe reports every failure as a result; none may escape.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            return WindowsError.FromException(exception, "Reading the file");
        }
    }

    public ProbeResult<IReadOnlyList<FileEntry>> List(string directory)
    {
        if (!IsFullPath(directory))
        {
            return ProbeFailure.Failed("The folder's location is not a path on this PC.");
        }

        try
        {
            var folder = new DirectoryInfo(directory);
            if (!folder.Exists)
            {
                return ProbeFailure.NotFound();
            }

            var entries = new List<FileEntry>();
            foreach (FileSystemInfo info in folder.EnumerateFileSystemInfos())
            {
                if (entries.Count == MaximumEntries)
                {
                    return ProbeFailure.Failed($"The folder has more than {MaximumEntries} entries and was not listed.");
                }

                bool isDirectory = info.Attributes.HasFlag(FileAttributes.Directory);
                entries.Add(new FileEntry(
                    info.Name,
                    isDirectory,
                    IsLink: info.Attributes.HasFlag(FileAttributes.ReparsePoint),
                    Length: info is FileInfo file ? file.Length : 0,
                    LastWrite: new DateTimeOffset(info.LastWriteTimeUtc, TimeSpan.Zero)));
            }

            entries.Sort((a, b) => StringComparer.OrdinalIgnoreCase.Compare(a.Name, b.Name));
            return ProbeResult<IReadOnlyList<FileEntry>>.Ok(entries);
        }
#pragma warning disable CA1031 // A probe reports every failure as a result; none may escape.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            return WindowsError.FromException(exception, "Listing the folder");
        }
    }

    /// <summary>
    /// Bytes to text: UTF-16 or UTF-8 when marked as such, otherwise UTF-8. Anything that is not
    /// valid text in that encoding fails, rather than being read with replacement characters.
    /// </summary>
    internal static ProbeResult<string> Decode(ReadOnlySpan<byte> bytes)
    {
        const string NotText = IFileProbe.NotTextDetail;

        try
        {
            string text;
            if (bytes.StartsWith<byte>([0xEF, 0xBB, 0xBF]))
            {
                text = StrictUtf8.GetString(bytes[3..]);
            }
            else if (bytes.StartsWith<byte>([0xFF, 0xFE]))
            {
                text = new UnicodeEncoding(bigEndian: false, byteOrderMark: false, throwOnInvalidBytes: true).GetString(bytes[2..]);
            }
            else if (bytes.StartsWith<byte>([0xFE, 0xFF]))
            {
                text = new UnicodeEncoding(bigEndian: true, byteOrderMark: false, throwOnInvalidBytes: true).GetString(bytes[2..]);
            }
            else
            {
                text = StrictUtf8.GetString(bytes);
            }

            return text.Contains('\0', StringComparison.Ordinal) ? ProbeFailure.Failed(NotText) : ProbeResult<string>.Ok(text);
        }
        catch (ArgumentException)
        {
            // DecoderFallbackException: invalid bytes for the encoding.
            return ProbeFailure.Failed(NotText);
        }
    }

    /// <summary>
    /// Only a path on a drive of this PC ("C:\..."). A network path ("\\server\share") is refused:
    /// opening one makes Windows sign in to that server as the user, and where a path comes
    /// from a file someone else may have written, that server would be theirs to choose.
    /// Device paths ("\\?\", "\\.\") are refused with it.
    /// </summary>
    internal static bool IsFullPath(string? path) =>
        path is { Length: >= 3 } &&
        char.IsAsciiLetter(path[0]) && path[1] == ':' && path[2] is '\\' or '/' &&
        Path.IsPathFullyQualified(path);
}
