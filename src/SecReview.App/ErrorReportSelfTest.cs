using SecReview.Checks;
using SecReview.CommandLine;
using SecReview.Diagnostics;
using SecReview.Probing;

namespace SecReview.App;

/// <summary>
/// <c>SecReview.exe --error-report-test file</c>: raises made-up errors that carry this PC's
/// real user name, computer name, profile path and a made-up secret (in their messages, in
/// errors inside errors, in data attached to them), sends them through the very same code real
/// reports take, and writes what would have gone over the network to the file instead. Nothing
/// is sent. The build then reads the file: the errors must be there, each once, and none of
/// what they carried may be.
/// </summary>
internal static class ErrorReportSelfTest
{
    /// <summary>A made-up address: reports need one to be built, and this one leads nowhere.</summary>
    private const string Address = "https://0123456789abcdef0123456789abcdef@reports.invalid/1";

    /// <summary>What an error might quote from a file a check read. Must never reach a report.</summary>
    public const string MadeUpSecret = "made-up-token-7c1f";

    /// <summary>How every made-up error's message begins. No error message may reach a report.</summary>
    public const string MessagePrefix = "Self-test error:";

    public static int Run(string path)
    {
        AppLog log = AppLog.ForThisProcess();
        try
        {
            string output = Path.GetFullPath(path);
            File.Delete(output);

            string names = $"{Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)}\\made-up.txt on {Environment.MachineName} for {Environment.UserName}, {MadeUpSecret}";
            var transport = new ErrorReporter.FileTransport(output);

            // Remembered for this run only: the self-test leaves nothing behind but its output.
            using (var reporter = new ErrorReporter(Address, log, PrivacyFilter.ForThisProcess(), new ErrorReportBudget(null, TimeProvider.System), transport))
            {
                reporter.Apply(new ErrorReportsChoice(SwitchOn: true, SettingsWereRead: true, NoticeSeen: true), new NoPolicy());
                if (reporter.State != ErrorReportsState.On)
                {
                    return ExitCode.UnhandledError;
                }

                // An error of the app itself.
                reporter.Report(Thrown(new InvalidOperationException($"{MessagePrefix} could not open {names}")));

                // An error inside a check, with data attached to it.
                var inCheck = new FormatException($"{MessagePrefix} {names} is malformed");
                inCheck.Data["file"] = names;
                reporter.Report(Thrown(inCheck), "selftest.check");

                // The same bug again, in the same check and in another: reported once.
                reporter.Report(Thrown(new FormatException($"{MessagePrefix} again")), "selftest.check");
                reporter.Report(Thrown(new FormatException($"{MessagePrefix} again")), "selftest.other");

                // Errors inside errors.
                reporter.Report(Thrown(new AggregateException(
                    $"{MessagePrefix} several things failed for {names}",
                    new InvalidCastException($"{MessagePrefix} inner, {names}"),
                    new TimeoutException($"{MessagePrefix} inner too", new ArgumentException($"{MessagePrefix} innermost, {names}")))));

                // A check identifier that is not one is not sent as one.
                reporter.Report(Thrown(new NotSupportedException($"{MessagePrefix} odd check")), names);

                reporter.ReportAbnormalEnd();
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
