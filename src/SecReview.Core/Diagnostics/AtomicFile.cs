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
            File.WriteAllBytes(temporary, contents);
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
