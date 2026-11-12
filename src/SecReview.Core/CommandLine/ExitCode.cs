namespace SecReview.CommandLine;

/// <summary>Process exit codes of SecReviewCli.</summary>
public static class ExitCode
{
    public const int Ok = 0;

    /// <summary>The command line was not understood.</summary>
    public const int Usage = 2;
}
