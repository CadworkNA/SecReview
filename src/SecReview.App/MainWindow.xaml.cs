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
    private readonly DispatcherQueueTimer _ticker;
    private int _frames;
    private bool _dialogOpen;

    /// <param name="role">How the window was started.</param>
    /// <param name="log">The local log.</param>
    /// <param name="reporter">Reports errors of SecReview itself, when that is on.</param>
    /// <param name="previousRunCrashed">Whether the previous run never closed down.</param>
    /// <param name="closed">Called when the window has been closed by the user.</param>
    internal MainWindow(UiRole role, AppLog log, ErrorReporter reporter, bool previousRunCrashed, Action? closed)
    {
        ArgumentNullException.ThrowIfNull(role);
        ArgumentNullException.ThrowIfNull(log);

        _role = role;
        _log = log;
        ViewModel = new MainViewModel(role, log, action => DispatcherQueue.TryEnqueue(() => action()), reporter, previousRunCrashed);
        InitializeComponent();

        AppWindow.Resize(InitialSize);
        Root.Loaded += OnLoaded;

        // Draws results that arrived between redraws and keeps "checked 5 minutes ago" true.
        _ticker = DispatcherQueue.CreateTimer();
        _ticker.Interval = TimeSpan.FromMilliseconds(300);
        _ticker.Tick += (_, _) => ViewModel.Tick();
        _ticker.Start();
        Closed += (_, _) =>
        {
            _ticker.Stop();
            closed?.Invoke();
        };
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

            // "Check again" and "More" are always there; with results, so are the five filters
            // and the rows.
            var problems = new List<string>(AccessibilityAudit.Problems(Root, atLeast: ViewModel.HasResults ? 12 : 2));
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
            (SettingsDialog(), 4),      // the switch, two "Stop ignoring" and Close
            (FeedbackDialog(out _, out _), 4),   // the text, the tick box, Send, Cancel
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

        // The commands behind "More": each must say what it is.
        if (MoreButton.Flyout is MenuFlyout menu)
        {
            foreach (MenuFlyoutItem command in menu.Items.OfType<MenuFlyoutItem>())
            {
                if (string.IsNullOrWhiteSpace(command.Text))
                {
                    problems.Add("A command in the More menu has no name.");
                }
            }
        }

        _ = NewReportPicker();
        ViewModel.StopIgnoring(anyCheck);
        ViewModel.Ignore(anyCheck, "Made up for the automated run");

        // What is inside the rows, the ignored ones included: every row on screen is opened.
        foreach (ScanFilter filter in (ScanFilter[])[ScanFilter.Ignored, ScanFilter.All])
        {
            ViewModel.Filter = filter;
            ViewModel.ExpandAll();
            await Task.Delay(AnimationSettleTime);
            problems.AddRange(AccessibilityAudit.Problems(Root, atLeast: 12).Select(problem => $"Rows open ({filter}): {problem}"));
        }

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

    private async void OnAdministratorChecksClicked(object sender, RoutedEventArgs e) => await ViewModel.RunAdministratorChecksAsync();

    private void OnAdministratorProblemClosed(InfoBar sender, object args) => ViewModel.DismissAdministratorProblem();

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
            ShowCopied(button);
        }
#pragma warning disable CA1031 // The clipboard can be held by another program; that is not worth more than a log line.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            _log.Error("The details could not be copied", exception);
        }
    }

    /// <summary>Says "Copied" on the button for a moment. It goes back by itself: rows are reused for other checks.</summary>
    private static async void ShowCopied(Button button)
    {
        object? before = button.Content;
        button.Content = "Copied";
        await Task.Delay(TimeSpan.FromSeconds(1.5));
        button.Content = before;
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
            await ShowAsync(Message(
                "Nothing to save yet",
                ViewModel.CanRun ? "There are no results yet. Run the checks first." : "The checks are still running. Save the report when they have finished."));
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

    private async void OnFeedbackClicked(object sender, RoutedEventArgs e)
    {
        if (await ShowAsync(FeedbackDialog(out TextBox text, out CheckBox include)) != ContentDialogResult.Primary)
        {
            return;
        }

        // What goes along is the very text the dialog showed, not a fresh look at the results:
        // a scan may have finished in between.
        bool sent = ViewModel.SendFeedback(text.Text, include.IsChecked == true ? include.Tag as string : null);
        await ShowAsync(sent
            ? Message("Thank you", "Your feedback is on its way.")
            : Message("Not sent", "Feedback could not be sent from this copy of SecReview."));
    }

    /// <summary>
    /// What the user wants to say, and whether to add which checks do not pass. What would be
    /// added is shown word for word before anything is sent.
    /// </summary>
    private ContentDialog FeedbackDialog(out TextBox text, out CheckBox include)
    {
        var secondary = (Brush)Application.Current.Resources["TextFillColorSecondaryBrush"];
        var typed = new TextBox
        {
            Header = "What should we know?",
            AcceptsReturn = true,
            TextWrapping = TextWrapping.Wrap,
            MinHeight = 120,
            MaxLength = ErrorReports.MaximumFeedbackLength,
        };
        string? results = ViewModel.ResultsForFeedback();
        var tick = new CheckBox { Content = "Include which checks do not pass", IsEnabled = results is not null, Tag = results };
        var preview = new TextBlock
        {
            Text = results ?? string.Empty,
            Foreground = secondary,
            TextWrapping = TextWrapping.Wrap,
            IsTextSelectionEnabled = true,
            Visibility = Visibility.Collapsed,
        };
        tick.Checked += (_, _) => preview.Visibility = Visibility.Visible;
        tick.Unchecked += (_, _) => preview.Visibility = Visibility.Collapsed;

        var panel = new StackPanel { Spacing = 12, MinWidth = 420 };
        panel.Children.Add(new TextBlock
        {
            Text = "Your text goes to the developers of SecReview with the versions of SecReview and Windows. Nothing else is added unless you tick the box, and then only what is shown below it.",
            TextWrapping = TextWrapping.Wrap,
        });
        panel.Children.Add(typed);
        panel.Children.Add(tick);
        panel.Children.Add(preview);

        var dialog = new ContentDialog
        {
            Title = "Send feedback",
            Content = new ScrollViewer { Content = panel, MaxHeight = 520 },
            PrimaryButtonText = "Send",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary,
            IsPrimaryButtonEnabled = false,
        };
        typed.TextChanged += (_, _) => dialog.IsPrimaryButtonEnabled = typed.Text.Trim().Length >= 10;
        text = typed;
        include = tick;
        return dialog;
    }

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

        // Error reports: the switch, what a report holds, and why the switch is off when it is not the user's to move.
        var reports = new ToggleSwitch
        {
            Header = "Report errors of SecReview to its developers",
            IsOn = ViewModel.CanChangeErrorReports && ViewModel.ErrorReportsSwitch,
            IsEnabled = ViewModel.CanChangeErrorReports,
        };
        var state = new TextBlock { Text = ViewModel.ErrorReportsDescription, TextWrapping = TextWrapping.Wrap, Foreground = secondary };
        reports.Toggled += (_, _) =>
        {
            ViewModel.SetErrorReports(reports.IsOn);
            state.Text = ViewModel.ErrorReportsDescription;
        };
        panel.Children.Add(reports);
        panel.Children.Add(state);
        panel.Children.Add(new TextBlock
        {
            Text = "A report holds the kind of error, where in SecReview it happened, and the versions of SecReview and Windows. Never the error's message, your results, the name of this PC, your name or a path.",
            TextWrapping = TextWrapping.Wrap,
            Foreground = secondary,
        });

        panel.Children.Add(new TextBlock
        {
            Text = "Ignored checks",
            Style = (Style)Application.Current.Resources["BodyStrongTextBlockStyle"],
            Margin = new Thickness(0, 12, 0, 0),
        });

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
