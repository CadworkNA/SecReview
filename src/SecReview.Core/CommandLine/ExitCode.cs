namespace SecReview.CommandLine;

/// <summary>Process exit codes of SecReviewCli.exe and SecReview.exe.</summary>
public static class ExitCode
{
    public const int Ok = 0;

    /// <summary>The command line was not understood.</summary>
    public const int Usage = 2;

    /// <summary><c>SecReview.exe --smoke-test</c>: the window did not draw within the limit.</summary>
    public const int SmokeTestTimedOut = 3;

    /// <summary><c>SecReviewCli --diagnose</c>: at least one reading failed outright.</summary>
    public const int ProbeFailed = 4;

    /// <summary>This Windows is older than SecReview supports.</summary>
    public const int UnsupportedWindows = 5;

    /// <summary><c>SecReviewCli --report</c>: the report file could not be written.</summary>
    public const int ReportNotWritten = 6;

    /// <summary><c>SecReview.exe --screenshot</c>: the picture could not be saved.</summary>
    public const int ScreenshotFailed = 7;

    /// <summary>An error nobody handled; the local log has the details.</summary>
    public const int UnhandledError = 8;

    /// <summary>An automated run of the window: the scan itself could not run; see the local log.</summary>
    public const int ScanFailed = 9;

    /// <summary><c>SecReviewCli --elevated-scan</c>: the results could not be sent to the app.</summary>
    public const int ElevatedScanFailed = 11;

    /// <summary><c>SecReviewCli --apply-update</c>: no update was installed; the app was told why on the pipe.</summary>
    public const int UpdateNotInstalled = 12;

    /// <summary>
    /// An automated run of the window: something a person can press has no name for a screen
    /// reader or cannot be reached with the keyboard; the local log names it.
    /// </summary>
    public const int AccessibilityFailed = 10;
}
