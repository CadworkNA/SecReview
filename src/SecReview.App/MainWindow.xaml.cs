using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using SecReview.App.ViewModels;
using SecReview.CommandLine;
using SecReview.Diagnostics;
using Windows.Graphics;

namespace SecReview.App;

public sealed partial class MainWindow : Window
{
    /// <summary>
    /// The rendering event fires before each frame is drawn, so the first callback proves
    /// nothing yet. Reaching a second one means a frame went through composition.
    /// </summary>
    private const int FramesBeforeDone = 2;

    private static readonly SizeInt32 InitialSize = new(860, 900);

    private static readonly TimeSpan AnimationSettleTime = TimeSpan.FromMilliseconds(900);

    private readonly UiRole _role;
    private readonly AppLog _log;
    private int _frames;

    public MainWindow(UiRole role, AppLog log)
    {
        ArgumentNullException.ThrowIfNull(role);
        ArgumentNullException.ThrowIfNull(log);

        _role = role;
        _log = log;
        ViewModel = new MainViewModel(role.Demo, log);
        InitializeComponent();

        AppWindow.Resize(InitialSize);
        Root.Loaded += OnLoaded;
    }

    public MainViewModel ViewModel { get; }

    private bool IsAutomatedRun => _role.SmokeTest || _role.ScreenshotPath is not null;

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        Root.Loaded -= OnLoaded;

        // ViewModel.RunAsync reports failures in the window and does not throw.
        await ViewModel.RunAsync();

        if (!IsAutomatedRun)
        {
            return;
        }

        if (ViewModel.HasFailed)
        {
            // A window that draws but cannot scan is a broken build, not a passing smoke test.
            Environment.Exit(ExitCode.ScanFailed);
        }

        // Let the results be laid out and drawn before taking the picture or closing.
        CompositionTarget.Rendering += OnRendering;
    }

    private void OnRendering(object? sender, object e)
    {
        if (++_frames < FramesBeforeDone)
        {
            return;
        }

        CompositionTarget.Rendering -= OnRendering;
        DispatcherQueue.TryEnqueue(DispatcherQueuePriority.Low, FinishAutomatedRun);
    }

    private async void FinishAutomatedRun()
    {
        try
        {
            if (_role.ScreenshotPath is not null)
            {
                // Rows that start open animate into place; a picture taken at once shows them empty.
                await Task.Delay(AnimationSettleTime);
                await Screenshot.SaveAsync(Root, _role.ScreenshotPath);
            }
        }
#pragma warning disable CA1031 // An automated run must end, not hang, whatever goes wrong.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            _log.Error("The screenshot could not be saved", exception);
            Environment.Exit(ExitCode.ScreenshotFailed);
        }

        Close();
    }

    private async void OnRunClicked(object sender, RoutedEventArgs e) => await ViewModel.RunAsync();

    private async void OnOpenSettingsClicked(object sender, RoutedEventArgs e)
    {
        // The address comes from the check catalogue. Only a Windows Settings page is ever
        // opened, whatever the data says.
        if (sender is Button { Tag: string link } &&
            Uri.TryCreate(link, UriKind.Absolute, out Uri? address) &&
            address.Scheme.Equals("ms-settings", StringComparison.OrdinalIgnoreCase))
        {
            await global::Windows.System.Launcher.LaunchUriAsync(address);
        }
    }
}
