using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;

namespace SecReview.App;

public sealed partial class MainWindow : Window
{
    /// <summary>
    /// The rendering event fires before each frame is drawn, so the first callback proves
    /// nothing yet. Reaching a second one means a frame went through composition.
    /// </summary>
    private const int FramesBeforeClose = 2;

    private int _frames;

    public MainWindow()
    {
        InitializeComponent();
    }

    public string VersionText { get; } = $"Version {ProductInfo.Version}";

    /// <summary>For the smoke test: closes the window once its content has been drawn.</summary>
    public void CloseAfterFirstFrame()
    {
        Root.Loaded += (_, _) => CompositionTarget.Rendering += OnRendering;
    }

    private void OnRendering(object? sender, object e)
    {
        if (++_frames < FramesBeforeClose)
        {
            return;
        }

        CompositionTarget.Rendering -= OnRendering;

        // Close from the dispatcher, after the work already queued for this frame.
        DispatcherQueue.TryEnqueue(DispatcherQueuePriority.Low, Close);
    }
}
