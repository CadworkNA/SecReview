using Microsoft.UI.Xaml;
using SecReview.CommandLine;
using SecReview.Diagnostics;

namespace SecReview.App;

public sealed partial class App : Application
{
    private readonly UiRole _role;
    private readonly AppLog _log;
    private readonly ErrorReporter _reporter;
    private readonly bool _previousRunCrashed;
    private MainWindow? _window;

    internal App(UiRole role, AppLog log, ErrorReporter reporter, bool previousRunCrashed)
    {
        _role = role;
        _log = log;
        _reporter = reporter;
        _previousRunCrashed = previousRunCrashed;
        InitializeComponent();

        // An error nobody handled is written to the local log and, when reporting is on,
        // reported. During an automated run the process then ends with a failure code, so a
        // broken build cannot look like a pass.
        UnhandledException += (_, e) =>
        {
            _log.Error("Unhandled error in the window", e.Exception);
            _reporter.Report(e.Exception);
            if (_role.SmokeTest || _role.ScreenshotPath is not null)
            {
                Environment.Exit(ExitCode.UnhandledError);
            }
        };
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        _window = new MainWindow(_role, _log, _reporter, _previousRunCrashed);
        _window.Activate();
    }
}
