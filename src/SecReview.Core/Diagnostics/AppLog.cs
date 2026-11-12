using System.Globalization;
using SecReview.Checks;

namespace SecReview.Diagnostics;

/// <summary>
/// A small local log for things that went wrong. It stays on the PC, is capped in size, and has
/// user and computer names removed before anything is written. Logging never throws: a log
/// that cannot be written must not take the app down with it.
/// </summary>
public sealed class AppLog
{
    /// <summary>When the log reaches this size the previous one is replaced and a new one starts.</summary>
    public const long MaximumBytes = 512 * 1024;

    private readonly Lock _gate = new();
    private readonly string _path;
    private readonly PrivacyFilter _privacy;
    private readonly TimeProvider _clock;

    public AppLog(string directory, PrivacyFilter privacy, TimeProvider clock)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        ArgumentNullException.ThrowIfNull(privacy);
        ArgumentNullException.ThrowIfNull(clock);

        _path = System.IO.Path.Combine(directory, "SecReview.log");
        _privacy = privacy;
        _clock = clock;
    }

    /// <summary>The log file.</summary>
    public string Path => _path;

    /// <summary>The log in SecReview's data folder, for this process.</summary>
    public static AppLog ForThisProcess() => new(
        System.IO.Path.Combine(AppData.Directory, "logs"), PrivacyFilter.ForThisProcess(), TimeProvider.System);

    public void Error(string where, Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        Write("ERROR", $"{where}: {exception.GetType().FullName}: {exception.Message}{Environment.NewLine}{exception.StackTrace}");
    }

    public void Info(string message) => Write("INFO", message);

    private void Write(string level, string message)
    {
        try
        {
            string line = string.Create(
                CultureInfo.InvariantCulture,
                $"{_clock.GetUtcNow():yyyy-MM-dd HH:mm:ss}Z {level} {ProductInfo.Version} {_privacy.Scrub(message)}{Environment.NewLine}");

            lock (_gate)
            {
                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(_path)!);

                var file = new FileInfo(_path);
                if (file.Exists && file.Length > MaximumBytes)
                {
                    File.Move(_path, _path + ".old", overwrite: true);
                }

                File.AppendAllText(_path, line);
            }
        }
#pragma warning disable CA1031 // Logging must never be the reason the app fails.
        catch (Exception)
#pragma warning restore CA1031
        {
        }
    }
}
