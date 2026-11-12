using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using SecReview.CommandLine;

namespace SecReview.App;

/// <summary>
/// Entry point. The role is decided here, before any XAML type is touched, so roles that need no
/// window never load the UI framework.
/// </summary>
internal static class Program
{
    /// <summary>A smoke test that has not finished by then is a failure.</summary>
    private static readonly TimeSpan SmokeTestLimit = TimeSpan.FromSeconds(30);

    private const int SmokeTestTimedOut = 3;

    [STAThread]
    private static int Main(string[] args)
    {
        switch (AppArguments.Parse(args))
        {
            case UiRole ui:
                return RunWindow(ui.SmokeTest);

            default:
                // A windowed app has no console to explain itself on; the exit code says it.
                return ExitCode.Usage;
        }
    }

    private static int RunWindow(bool smokeTest)
    {
        using Timer? watchdog = smokeTest
            ? new Timer(_ => Environment.Exit(SmokeTestTimedOut), null, SmokeTestLimit, Timeout.InfiniteTimeSpan)
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
