using Microsoft.UI.Xaml;
using SecReview.CommandLine;
using SecReview.Diagnostics;

namespace SecReview.App;

public sealed partial class App : Application
{
    private readonly UiRole _role;
    private readonly AppLog _log;
    private MainWindow? _window;

    public App(UiRole role, AppLog log)
    {
        _role = role;
        _log = log;
        InitializeComponent();

        // An error nobody handled is written to the local log. During an automated run the
        // process then ends with a failure code, so a broken build cannot look like a pass.
        UnhandledException += (_, e) =>
        {
            _log.Error("Unhandled error in the window", e.Exception);
            if (_role.SmokeTest || _role.ScreenshotPath is not null)
            {
                Environment.Exit(ExitCode.UnhandledError);
            }
        };
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        _window = new MainWindow(_role, _log);
        _window.Activate();
    }
}
