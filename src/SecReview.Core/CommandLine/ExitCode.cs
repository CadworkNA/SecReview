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
}
