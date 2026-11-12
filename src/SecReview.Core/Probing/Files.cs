namespace SecReview.Probing;

/// <summary>One entry of a folder.</summary>
/// <param name="Name">The name without the folder.</param>
/// <param name="IsDirectory">Whether it is a folder.</param>
/// <param name="IsLink">
/// Whether it is a link or junction to somewhere else. Scans do not follow these, so a link
/// cannot lead them out of the folder they were asked to read or round in a circle.
/// </param>
/// <param name="Length">Size in bytes; zero for a folder.</param>
/// <param name="LastWrite">When it was last changed.</param>
public sealed record FileEntry(string Name, bool IsDirectory, bool IsLink, long Length, DateTimeOffset LastWrite);

/// <summary>
/// Reads files and folders. Only reads: nothing is created, changed, opened for writing or
/// executed. Paths are absolute.
/// </summary>
public interface IFileProbe
{
    /// <summary>The most a configuration file is expected to hold. Larger files are not read.</summary>
    const int DefaultMaximumBytes = 1024 * 1024;

    /// <summary>
    /// The <see cref="ProbeResult{T}.Detail"/> of a read that failed because the file is not
    /// text. A caller looking for one kind of text file among others can tell this apart from a
    /// file it was not allowed to read.
    /// </summary>
    const string NotTextDetail = "The file is not text and was not read.";

    /// <summary>How the <see cref="ProbeResult{T}.Detail"/> of a read begins that failed because the file is too large.</summary>
    const string TooLargeDetailStart = "The file is larger than";

    /// <summary>
    /// The text of a file. Fails, rather than returning part of it, when the file is larger than
    /// <paramref name="maximumBytes"/> or is not text: a check must never judge half a file.
    /// </summary>
    ProbeResult<string> ReadText(string path, int maximumBytes = DefaultMaximumBytes);

    /// <summary>The entries of a folder, sorted by name. <see cref="ProbeStatus.NotFound"/> if there is no such folder.</summary>
    ProbeResult<IReadOnlyList<FileEntry>> List(string directory);
}

/// <summary>Folders whose place differs from PC to PC and user to user.</summary>
public enum KnownFolder
{
    /// <summary>The signed-in user's profile, for example <c>C:\Users\name</c>.</summary>
    UserProfile,

    /// <summary><c>%APPDATA%</c>.</summary>
    RoamingAppData,

    /// <summary><c>%LOCALAPPDATA%</c>.</summary>
    LocalAppData,

    /// <summary><c>%ProgramData%</c>.</summary>
    ProgramData,

    /// <summary><c>%ProgramFiles%</c>.</summary>
    ProgramFiles,

    /// <summary><c>%ProgramFiles(x86)%</c>.</summary>
    ProgramFilesX86,

    /// <summary>The Windows folder.</summary>
    Windows,
}

/// <summary>What this process was started with and where things are for the signed-in user.</summary>
public interface IEnvironmentProbe
{
    /// <summary>A known folder; <see cref="ProbeStatus.NotFound"/> if Windows does not report one.</summary>
    ProbeResult<string> Folder(KnownFolder folder);

    /// <summary>
    /// An environment variable as this process sees it, or null if it is not set. Never used for
    /// secrets: checks that look at token-carrying variables report the name only.
    /// </summary>
    string? Variable(string name);

    /// <summary>How long Windows has been running since it last started or restarted.</summary>
    ProbeResult<TimeSpan> Uptime();
}
