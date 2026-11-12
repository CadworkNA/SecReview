using SecReview.Checks;
using SecReview.CommandLine;
using SecReview.Diagnostics;
using SecReview.Probing;

namespace SecReview.App;

/// <summary>
/// <c>SecReview.exe --error-report-test file</c>: raises made-up errors that carry this PC's
/// real user name, computer name, profile path and a made-up secret, sends them through the
/// very same code real reports take, and writes what would have gone over the network to the
/// file instead. Nothing is sent. The build then reads the file: the errors must be there and
/// none of those names may be.
/// </summary>
internal static class ErrorReportSelfTest
{
    /// <summary>A made-up address: reports need one to be built, and this one leads nowhere.</summary>
    private const string Address = "https://0123456789abcdef0123456789abcdef@reports.invalid/1";

    /// <summary>What a check's error message might quote from a file it read. Must never reach a report.</summary>
    public const string MadeUpSecret = "made-up-token-7c1f";

    public static int Run(string path)
    {
        AppLog log = AppLog.ForThisProcess();
        try
        {
            string output = Path.GetFullPath(path);
            File.Delete(output);

            string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            using (var reporter = new ErrorReporter(Address, log, PrivacyFilter.ForThisProcess(), new ErrorReporter.FileTransport(output)))
            {
                reporter.Apply(settingOn: true, new NoPolicy());
                if (reporter.State != ErrorReportsState.On)
                {
                    return ExitCode.UnhandledError;
                }

                // An error of the app itself: its message stays, without the names.
                reporter.Report(Thrown(new InvalidOperationException(
                    $"Self-test: could not open {profile}\\made-up.txt on {Environment.MachineName} for {Environment.UserName}")));

                // An error inside a check: its message can quote what the check read, so it is dropped.
                reporter.Report(Thrown(new FormatException($"Self-test: {MadeUpSecret} in {profile}\\.npmrc is malformed")), "selftest.check");

                // The same error again: reported once.
                reporter.Report(Thrown(new FormatException("Self-test: again")), "selftest.check");

                reporter.ReportAbnormalEnd();
                reporter.SendFeedback($"Self-test feedback written by {Environment.UserName} on {Environment.MachineName}", "firewall.enabled: Fail");
            }

            return File.Exists(output) ? ExitCode.Ok : ExitCode.UnhandledError;
        }
#pragma warning disable CA1031 // A self-test reports any failure through its exit code.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            log.Error("The error-report self-test failed", exception);
            return ExitCode.UnhandledError;
        }
    }

    /// <summary>The error with a stack, as a real one has. Always thrown from this one place.</summary>
    private static Exception Thrown(Exception error)
    {
        try
        {
            throw error;
        }
        catch (Exception caught) when (ReferenceEquals(caught, error))
        {
            return caught;
        }
    }

    /// <summary>A registry with no policy in it: the self-test must not depend on this PC's settings.</summary>
    private sealed class NoPolicy : IRegistryProbe
    {
        public ProbeResult<RegistryValue> GetValue(RegistryRoot root, string keyPath, string valueName) => ProbeFailure.NotFound();

        public ProbeResult<IReadOnlyList<string>> GetSubKeyNames(RegistryRoot root, string keyPath) => ProbeFailure.NotFound();

        public ProbeResult<IReadOnlyList<string>> GetValueNames(RegistryRoot root, string keyPath) => ProbeFailure.NotFound();
    }
}
