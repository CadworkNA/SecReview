namespace SecReview.Diagnostics;

/// <summary>
/// Writes one of SecReview's own files so that a reader never sees half of it: the new contents
/// go to a temporary file beside it, which then takes the file's place in one step.
/// </summary>
public static class AtomicFile
{
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

            File.Move(temporary, fullPath, overwrite: true);
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
