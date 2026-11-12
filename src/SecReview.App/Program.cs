using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using SecReview.CommandLine;

namespace SecReview.App;

/// <summary>
/// Entry point. The role is decided here, before any XAML type is touched, so a role that needs
/// no window never starts XAML. (The Windows App SDK's own start-up code still runs before
/// <c>Main</c> in every role; it locates the SDK's files but does not start the UI framework.)
/// </summary>
internal static class Program
{
    /// <summary>A smoke test that has not finished by then is a failure.</summary>
    private static readonly TimeSpan SmokeTestLimit = TimeSpan.FromSeconds(30);

    [STAThread]
    private static int Main(string[] args)
    {
        switch (AppArguments.Parse(args))
        {
            case UiRole ui:
                return RunWindow(ui.SmokeTest);

            case InvalidRole:
                // A windowed app has no console to explain itself on; the exit code says it.
                return ExitCode.Usage;

            default:
                throw new InvalidOperationException("Unhandled role.");
        }
    }

    private static int RunWindow(bool smokeTest)
    {
        using Timer? watchdog = smokeTest
            ? new Timer(
                _ => Environment.Exit(ExitCode.SmokeTestTimedOut), null, SmokeTestLimit, Timeout.InfiniteTimeSpan)
            : null;

        WinRT.ComWrappersSupport.InitializeComWrappers();
        Application.Start(startParameters =>
        {
            SynchronizationContext.SetSynchronizationContext(
                new DispatcherQueueSynchronizationContext(DispatcherQueue.GetForCurrentThread()));
            _ = new App(smokeTest);
        });

        return ExitCode.Ok;
    }
}
