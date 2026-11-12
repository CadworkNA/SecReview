using Microsoft.UI.Xaml;

namespace SecReview.App;

public sealed partial class App : Application
{
    private readonly bool _smokeTest;
    private MainWindow? _window;

    public App(bool smokeTest)
    {
        _smokeTest = smokeTest;
        InitializeComponent();
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        _window = new MainWindow();
        if (_smokeTest)
        {
            _window.CloseAfterFirstFrame();
        }

        _window.Activate();
    }
}
