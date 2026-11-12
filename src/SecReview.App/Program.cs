using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using SecReview.CommandLine;
using SecReview.Diagnostics;

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

    [STAThread]
    private static int Main(string[] args)
    {
        switch (AppArguments.Parse(args))
        {
            case UiRole ui:
                return RunWindow(ui);

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

        AppLog log = AppLog.ForThisProcess();
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
        {
            if (e.ExceptionObject is Exception exception)
            {
                log.Error("Unhandled error", exception);
            }
        };

        try
        {
            WinRT.ComWrappersSupport.InitializeComWrappers();
            Application.Start(startParameters =>
            {
                SynchronizationContext.SetSynchronizationContext(
                    new DispatcherQueueSynchronizationContext(DispatcherQueue.GetForCurrentThread()));
                _ = new App(role, log);
            });
        }
#pragma warning disable CA1031 // Last resort: record why the window could not run, then fail visibly.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            log.Error("The window could not start", exception);
            return ExitCode.UnhandledError;
        }

        return ExitCode.Ok;
    }
}
