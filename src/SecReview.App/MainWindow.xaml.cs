using System.Text;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.Windows.Storage.Pickers;
using SecReview.App.ViewModels;
using SecReview.CommandLine;
using SecReview.Diagnostics;
using SecReview.Scanning;
using SecReview.Settings;
using Windows.ApplicationModel.DataTransfer;
using Windows.Graphics;

namespace SecReview.App;

public sealed partial class MainWindow : Window
{
    /// <summary>
    /// The rendering event fires before each frame is drawn, so the first callback proves
    /// nothing yet. Reaching a second one means a frame went through composition.
    /// </summary>
    private const int FramesBeforeDone = 2;

    private static readonly SizeInt32 InitialSize = new(900, 960);

    private static readonly TimeSpan AnimationSettleTime = TimeSpan.FromMilliseconds(900);

    private readonly UiRole _role;
    private readonly AppLog _log;
    private int _frames;
    private bool _dialogOpen;

    public MainWindow(UiRole role, AppLog log)
    {
        ArgumentNullException.ThrowIfNull(role);
        ArgumentNullException.ThrowIfNull(log);

        _role = role;
        _log = log;
        ViewModel = new MainViewModel(role, log, action => DispatcherQueue.TryEnqueue(() => action()));
        InitializeComponent();

        AppWindow.Resize(InitialSize);
        Root.Loaded += OnLoaded;
    }

    public MainViewModel ViewModel { get; }

    private bool IsAutomatedRun => _role.SmokeTest || _role.ScreenshotPath is not null;

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        Root.Loaded -= OnLoaded;

        // ViewModel.StartAsync reports failures in the window and does not throw.
        await ViewModel.StartAsync();

        if (!IsAutomatedRun)
        {
            return;
        }

        if (ViewModel.HasFailed && !_role.Demo)
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
            // Rows that start open animate into place; a picture taken at once shows them empty,
            // and their buttons are not there yet to be looked at.
            await Task.Delay(AnimationSettleTime);

            // "Check again" and "More" are always there.
            var problems = new List<string>(AccessibilityAudit.Problems(Root, atLeast: 2));
            if (_role is { Demo: true, DemoState: DemoState.Dialogs })
            {
                problems.AddRange(await ExerciseDialogsAsync());
                await Task.Delay(AnimationSettleTime);
            }

            if (problems.Count > 0)
            {
                _log.Error("The window is not accessible", new InvalidOperationException(string.Join(" ", problems.Take(20))));
                Environment.Exit(ExitCode.AccessibilityFailed);
            }

            if (_role.ScreenshotPath is not null)
            {
                await Screenshot.SaveAsync(Root, _role.ScreenshotPath);
            }
        }
#pragma warning disable CA1031 // An automated run must end, not hang, whatever goes wrong.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            _log.Error("The automated run of the window failed", exception);
            Environment.Exit(ExitCode.ScreenshotFailed);
        }

        Close();
    }

    /// <summary>
    /// Opens every dialog once, looks at it the way a screen reader does, and closes it; also
    /// goes through what the menu commands do short of showing Windows' own file dialog. For
    /// automated runs: nobody can click in those, and a dialog that fails to open would
    /// otherwise only show on a user's PC.
    /// </summary>
    private async Task<IReadOnlyList<string>> ExerciseDialogsAsync()
    {
        var problems = new List<string>();
        string anyCheck = ViewModel.IgnoredRows[0].Id;

        (ContentDialog Dialog, int Controls)[] dialogs =
        [
            (IgnoreDialog(out _), 3),   // the reason, Ignore, Cancel
            (SettingsDialog(), 3),      // two "Stop ignoring" and Close
            (AboutDialog(), 1),
            (Message("Made up", "A message."), 1),
        ];
        foreach ((ContentDialog dialog, int controls) in dialogs)
        {
            Task<ContentDialogResult> shown = ShowAsync(dialog);
            await Task.Delay(AnimationSettleTime);
            problems.AddRange(AccessibilityAudit.Problems(dialog, controls).Select(problem => $"{dialog.Title}: {problem}"));
            dialog.Hide();
            await shown;
        }

        if (ViewModel.DetailsOf(anyCheck) is not { Length: > 0 } || ViewModel.ReportJson() is not { Length: > 0 })
        {
            problems.Add("The details of a check or the report came back empty.");
        }

        _ = NewReportPicker();
        ViewModel.StopIgnoring(anyCheck);
        ViewModel.Ignore(anyCheck, "Made up for the automated run");
        return problems;
    }

    private async void OnRunClicked(object sender, RoutedEventArgs e) => await ViewModel.RunAsync();

    private void OnFilterChanged(SelectorBar sender, SelectorBarSelectionChangedEventArgs args)
    {
        SelectorBarItem selected = sender.SelectedItem;
        ViewModel.Filter =
            selected == FilterAttention ? ScanFilter.NeedsAttention
            : selected == FilterAdmin ? ScanFilter.NeedsAdmin
            : selected == FilterPassed ? ScanFilter.Passed
            : selected == FilterIgnored ? ScanFilter.Ignored
            : ScanFilter.All;
        ListScroller.ChangeView(null, 0, null, disableAnimation: true);
    }

    private void OnFirstRunClosed(InfoBar sender, object args) => ViewModel.DismissFirstRun();

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

    private async void OnCheckAgainClicked(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string id })
        {
            await ViewModel.CheckAgainAsync(id);
        }
    }

    private void OnCopyDetailsClicked(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string id } button || ViewModel.DetailsOf(id) is not { } details)
        {
            return;
        }

        try
        {
            var package = new DataPackage();
            package.SetText(details);
            Clipboard.SetContent(package);
            button.Content = "Copied";
        }
#pragma warning disable CA1031 // The clipboard can be held by another program; that is not worth more than a log line.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            _log.Error("The details could not be copied", exception);
        }
    }

    private async void OnIgnoreClicked(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string id })
        {
            return;
        }

        if (await ShowAsync(IgnoreDialog(out TextBox reason)) == ContentDialogResult.Primary)
        {
            ViewModel.Ignore(id, reason.Text);
        }
    }

    private void OnStopIgnoringClicked(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string id })
        {
            ViewModel.StopIgnoring(id);
        }
    }

    private async void OnSaveReportClicked(object sender, RoutedEventArgs e)
    {
        if (ViewModel.ReportJson() is not { } report)
        {
            await ShowAsync(Message("Nothing to save yet", "There are no results yet. Run the checks first."));
            return;
        }

        try
        {
            if (await NewReportPicker().PickSaveFileAsync() is { Path: { Length: > 0 } path })
            {
                AtomicFile.Write(path, Encoding.UTF8.GetBytes(report));
            }
        }
#pragma warning disable CA1031 // Whatever keeps the file from being written is said, not thrown.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            _log.Error("The report could not be saved", exception);
            await ShowAsync(Message("The report could not be saved", exception.Message));
        }
    }

    private async void OnSettingsClicked(object sender, RoutedEventArgs e) => await ShowAsync(SettingsDialog());

    private async void OnAboutClicked(object sender, RoutedEventArgs e) => await ShowAsync(AboutDialog());

    /// <summary>Windows' "Save as" dialog for the report.</summary>
    private FileSavePicker NewReportPicker()
    {
        var picker = new FileSavePicker(AppWindow.Id)
        {
            SuggestedFileName = "SecReview report",
            DefaultFileExtension = ".json",
            SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
        };
        picker.FileTypeChoices.Add("Report", [".json"]);
        return picker;
    }

    /// <summary>Asks why a check may be left out of the count. "Ignore" stays off until a reason is typed.</summary>
    private static ContentDialog IgnoreDialog(out TextBox reason)
    {
        var typed = new TextBox
        {
            Header = "Why is this acceptable on this PC?",
            PlaceholderText = "For example: handled by the lab's own firewall",
            MaxLength = AppSettings.MaximumReasonLength,
        };
        var dialog = new ContentDialog
        {
            Title = "Ignore this check?",
            Content = new StackPanel
            {
                Spacing = 12,
                MinWidth = 360,
                Children =
                {
                    new TextBlock
                    {
                        Text = "The check keeps running and stays visible under Ignored, but it no longer counts. The reason is kept with it.",
                        TextWrapping = TextWrapping.Wrap,
                    },
                    typed,
                },
            },
            PrimaryButtonText = "Ignore",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary,
            IsPrimaryButtonEnabled = false,
        };
        typed.TextChanged += (_, _) => dialog.IsPrimaryButtonEnabled = AppSettings.Clean(typed.Text).Length >= 3;
        reason = typed;
        return dialog;
    }

    /// <summary>The settings: for now the ignored checks, each with its reason and a way back.</summary>
    private ContentDialog SettingsDialog()
    {
        var secondary = (Brush)Application.Current.Resources["TextFillColorSecondaryBrush"];
        var panel = new StackPanel { Spacing = 12, MinWidth = 420 };
        panel.Children.Add(new TextBlock { Text = "Ignored checks", Style = (Style)Application.Current.Resources["BodyStrongTextBlockStyle"] });

        var none = new TextBlock { Text = "No check is ignored.", Foreground = secondary };
        IReadOnlyList<IgnoredRow> rows = ViewModel.IgnoredRows;
        if (rows.Count == 0)
        {
            panel.Children.Add(none);
        }

        foreach (IgnoredRow row in rows)
        {
            var line = new Grid { ColumnSpacing = 12 };
            line.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            line.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var text = new StackPanel { Spacing = 2 };
            text.Children.Add(new TextBlock { Text = row.Title, TextWrapping = TextWrapping.Wrap });
            text.Children.Add(new TextBlock { Text = row.Reason, TextWrapping = TextWrapping.Wrap, Foreground = secondary });
            line.Children.Add(text);

            var stop = new Button { Content = "Stop ignoring", VerticalAlignment = VerticalAlignment.Center };
            AutomationProperties.SetName(stop, $"Stop ignoring: {row.Title}");
            Grid.SetColumn(stop, 1);
            stop.Click += (_, _) =>
            {
                ViewModel.StopIgnoring(row.Id);
                panel.Children.Remove(line);
                if (ViewModel.IgnoredRows.Count == 0)
                {
                    panel.Children.Add(none);
                }
            };
            line.Children.Add(stop);
            panel.Children.Add(line);
        }

        return new ContentDialog
        {
            Title = "Settings",
            Content = new ScrollViewer { Content = panel, MaxHeight = 480 },
            CloseButtonText = "Close",
            DefaultButton = ContentDialogButton.Close,
        };
    }

    private static ContentDialog AboutDialog()
    {
        var panel = new StackPanel { Spacing = 8, MaxWidth = 440 };
        foreach (string line in (string[])
        [
            $"Version {ProductInfo.Version}",
            "SecReview checks this PC's security settings and explains what it finds. It never changes a setting, and the results stay on this PC.",
            "Open source under the MIT licence.",
            "The list of known-malicious packages comes from the OpenSSF malicious-packages feed (Apache-2.0).",
        ])
        {
            panel.Children.Add(new TextBlock { Text = line, TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true });
        }

        return new ContentDialog
        {
            Title = "About SecReview",
            Content = panel,
            CloseButtonText = "Close",
            DefaultButton = ContentDialogButton.Close,
        };
    }

    private static ContentDialog Message(string title, string text) => new()
    {
        Title = title,
        Content = new TextBlock { Text = text, TextWrapping = TextWrapping.Wrap },
        CloseButtonText = "Close",
        DefaultButton = ContentDialogButton.Close,
    };

    /// <summary>Shows a dialog over the window. Only one can be open; a second request is dropped.</summary>
    private async Task<ContentDialogResult> ShowAsync(ContentDialog dialog)
    {
        if (_dialogOpen)
        {
            return ContentDialogResult.None;
        }

        _dialogOpen = true;
        try
        {
            dialog.XamlRoot = Root.XamlRoot;
            return await dialog.ShowAsync();
        }
        finally
        {
            _dialogOpen = false;
        }
    }
}
