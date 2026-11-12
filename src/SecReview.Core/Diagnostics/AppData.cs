namespace SecReview.Diagnostics;

/// <summary>Where SecReview keeps its own files (log, later results and settings).</summary>
public static class AppData
{
    /// <summary>
    /// Set during development and in tests to keep SecReview's files in a chosen folder
    /// instead of the user's profile. Only the unelevated app reads it.
    /// </summary>
    public const string OverrideVariable = "SECREVIEW_DATA_DIR";

    /// <summary>
    /// The data folder: the override if set, otherwise <c>%LOCALAPPDATA%\SecReview</c>.
    /// </summary>
    public static string Directory
    {
        get
        {
            string? chosen = Environment.GetEnvironmentVariable(OverrideVariable);
            return !string.IsNullOrWhiteSpace(chosen)
                ? Path.GetFullPath(chosen)
                : Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), ProductInfo.Name);
        }
    }
}
