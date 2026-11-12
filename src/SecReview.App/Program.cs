using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using SecReview.Checks;
using SecReview.CommandLine;
using SecReview.Diagnostics;
using SecReview.Instances;

namespace SecReview.App;

/// <summary>
/// Entry point. The role is decided here, before any XAML type is touched, so a role that needs
/// no window never starts XAML. (The Windows App SDK's own start-up code still runs before
/// <c>Main</c> in every role; it locates the SDK's files but does not start the UI framework.)
/// </summary>
internal static class Program
{
    /// <summary>An automated run (smoke test, screenshot) that has not finished by then has failed.</summary>
    private static readonly TimeSpan AutomatedRunLimit = TimeSpan.FromSeconds(60);

    /// <summary>A second start waits this long for the open window to answer before opening its own.</summary>
    private static readonly TimeSpan HandOverLimit = TimeSpan.FromSeconds(3);

    [STAThread]
    private static int Main(string[] args)
    {
        switch (AppArguments.Parse(args))
        {
            case UiRole ui:
                return RunWindow(ui);

            case TrayRole tray:
                return TrayApp.Run(tray);

            case ErrorReportTestRole test:
                return ErrorReportSelfTest.Run(test.OutputPath);

            case InvalidRole:
                // A windowed app has no console to explain itself on; the exit code says it.
                return ExitCode.Usage;

            default:
                throw new InvalidOperationException("Unhandled role.");
        }
    }

    private static int RunWindow(UiRole role)
    {
        bool automated = role.SmokeTest || role.ScreenshotPath is not null;
        using Timer? watchdog = automated
            ? new Timer(
                _ => Environment.Exit(ExitCode.SmokeTestTimedOut), null, AutomatedRunLimit, Timeout.InfiniteTimeSpan)
            : null;

        // One window per user: a second start (from the notification-area icon, or the Start
        // menu) brings the open one forward, on the check it was asked to show, and ends.
        // Made-up results and automated runs are windows of their own.
        using SingleInstance? claim = role.Demo || automated ? null : ClaimOrHandOver(role);
        if (claim is null && !role.Demo && !automated)
        {
            return ExitCode.Ok;
        }

        AppLog log = AppLog.ForThisProcess();

        // Made-up results and automated runs report nothing, whatever the build: the first are
        // for looking at the window, the second run on build machines, whose errors are the
        // build's business and not a user's.
        using var reporter = new ErrorReporter(
            role.Demo || automated ? null : ErrorReporter.CompiledAddress,
            log,
            PrivacyFilter.ForThisProcess(),
            new ErrorReportBudget(AppData.Directory, TimeProvider.System));

        // A run that is being looked at by a person leaves a marker while its window is open;
        // one found at the next start, with its process gone, is a run that crashed.
        RunMarker? marker = role.Demo || automated ? null : RunMarker.ForThisProcess();
        bool previousRunCrashed = marker?.Begin() ?? false;

        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
        {
            if (e.ExceptionObject is Exception exception)
            {
                log.Error("Unhandled error", exception);
                reporter.Report(exception);
                reporter.Flush(); // the process is about to end: send what is waiting
            }
        };

        try
        {
            WinRT.ComWrappersSupport.InitializeComWrappers();
            Application.Start(startParameters =>
            {
                SynchronizationContext.SetSynchronizationContext(
                    new DispatcherQueueSynchronizationContext(DispatcherQueue.GetForCurrentThread()));
                // The marker goes when the user closes the window, not when the process has
                // finished winding down: ending Windows right after is not a crash.
                _ = new App(role, log, reporter, previousRunCrashed, () => marker?.End());
            });
        }
#pragma warning disable CA1031 // Last resort: record why the window could not run, then fail visibly.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            log.Error("The window could not start", exception);
            reporter.Report(exception);
            return ExitCode.UnhandledError;
        }

        marker?.End();
        return ExitCode.Ok;
    }

    /// <summary>
    /// The claim to be the window, or null after handing over to the window that is open. When
    /// that window does not answer (it is closing, or stuck), this start opens its own.
    /// </summary>
    private static SingleInstance? ClaimOrHandOver(UiRole role)
    {
        string data = AppData.Directory;
        long started = Environment.TickCount64;
        while (true)
        {
            if (SingleInstance.TryClaim(InstanceNames.Window(data)) is { } claim)
            {
                return claim;
            }

            Foreground.HandOver();
            if (ShowRequests.Send(InstanceNames.WindowShow(data), InstanceNames.WindowRequest(data), role.ShowCheck))
            {
                return null;
            }

            if (Environment.TickCount64 - started > HandOverLimit.TotalMilliseconds)
            {
                // Nobody answered: a window of its own, without the claim, beats no window.
                return SingleInstance.Unclaimed;
            }

            Thread.Sleep(100);
        }
    }
}
