namespace SecReview.CommandLine;

/// <summary>Process exit codes of SecReviewCli.exe and SecReview.exe.</summary>
public static class ExitCode
{
    public const int Ok = 0;

    /// <summary>The command line was not understood.</summary>
    public const int Usage = 2;

    /// <summary><c>SecReview.exe --smoke-test</c>: the window did not draw within the limit.</summary>
    public const int SmokeTestTimedOut = 3;
}
