using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;

namespace SecReview.App;

public sealed partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
    }

    public string VersionText { get; } = $"Version {ProductInfo.Version}";

    /// <summary>For the smoke test: closes the window once its content has rendered a frame.</summary>
    public void CloseAfterFirstFrame()
    {
        Root.Loaded += (_, _) => CompositionTarget.Rendering += OnFirstFrame;
    }

    private void OnFirstFrame(object? sender, object e)
    {
        CompositionTarget.Rendering -= OnFirstFrame;
        Close();
    }
}
