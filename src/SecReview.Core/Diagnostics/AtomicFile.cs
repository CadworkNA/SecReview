namespace SecReview.Diagnostics;

/// <summary>
/// Writes one of SecReview's own files so that a reader never sees half of it: the new contents
/// go to a temporary file beside it, which then takes the file's place in one step.
/// The window and the notification-area icon share these files. Windows does not replace a
/// file while anyone has it open, so a reader holds it only for the instant of reading, and
/// a writer that finds it in use tries again a few times.
/// </summary>
public static class AtomicFile
{
    private const int Attempts = 5;

    /// <summary>The file's contents, read in one go and without keeping other readers out.</summary>
    public static byte[] Read(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        byte[] contents = new byte[stream.Length];
        stream.ReadExactly(contents);
        return contents;
    }

    public static void Write(string path, ReadOnlySpan<byte> contents)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        string fullPath = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        string temporary = fullPath + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            // On disk before it takes the file's place: a power cut must not leave an empty file under the real name.
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                stream.Write(contents);
                stream.Flush(flushToDisk: true);
            }

            for (int attempt = 1; ; attempt++)
            {
                try
                {
                    File.Move(temporary, fullPath, overwrite: true);
                    break;
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException && attempt < Attempts)
                {
                    // Another program has the file open just now (the other SecReview process
                    // reading it, an antivirus looking at it).
                    Thread.Sleep(40 * attempt);
                }
            }
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }
}
