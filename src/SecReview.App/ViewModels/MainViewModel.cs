using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using SecReview.Checks;
using SecReview.Diagnostics;
using SecReview.Probing.Windows;
using SecReview.Scanning;

namespace SecReview.App.ViewModels;

/// <summary>What the main window shows: a headline, the checks, and whether a scan is running.</summary>
public sealed partial class MainViewModel : INotifyPropertyChanged
{
    private readonly bool _demo;
    private readonly AppLog _log;
    private string _headline = "Checking this PC…";
    private string _detail = string.Empty;
    private bool _isBusy;
    private bool _hasFailed;
    private string _failure = string.Empty;

    public MainViewModel(bool demo, AppLog log)
    {
        ArgumentNullException.ThrowIfNull(log);

        _demo = demo;
        _log = log;
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    /// <summary>
    /// The rows (<see cref="CheckItem"/>). Typed as objects because WinUI list controls reject a
    /// collection of a custom type ("not a supported vector").
    /// </summary>
    public ObservableCollection<object> Checks { get; } = [];

    public string Headline
    {
        get => _headline;
        private set => Set(ref _headline, value, nameof(Headline));
    }

    /// <summary>The line under the headline: counts and when the scan finished.</summary>
    public string Detail
    {
        get => _detail;
        private set => Set(ref _detail, value, nameof(Detail));
    }

    public bool IsBusy
    {
        get => _isBusy;
        private set
        {
            if (Set(ref _isBusy, value, nameof(IsBusy)))
            {
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(CanRun)));
            }
        }
    }

    public bool CanRun => !IsBusy;

    /// <summary>True when the scan itself could not run; <see cref="Failure"/> says why.</summary>
    public bool HasFailed
    {
        get => _hasFailed;
        private set => Set(ref _hasFailed, value, nameof(HasFailed));
    }

    public string Failure
    {
        get => _failure;
        private set => Set(ref _failure, value, nameof(Failure));
    }

    /// <summary>Runs a scan and shows it. Never throws: a failure is shown in the window.</summary>
    public async Task RunAsync()
    {
        if (IsBusy)
        {
            return;
        }

        IsBusy = true;
        HasFailed = false;
        Headline = "Checking this PC…";
        Detail = string.Empty;

        try
        {
            ScanResult scan = _demo
                ? DemoScan.Create(TimeProvider.System)
                : await Task.Run(ScanThisPcAsync).ConfigureAwait(true);
            Show(scan);
        }
#pragma warning disable CA1031 // The window must stay usable whatever goes wrong in a scan.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            _log.Error("The scan could not run", exception);
            Checks.Clear();
            Headline = "The checks could not run";
            Failure = exception.Message;
            HasFailed = true;
        }
        finally
        {
            IsBusy = false;
        }
    }

    private static Task<ScanResult> ScanThisPcAsync()
    {
        if (!WindowsProbes.IsSupported)
        {
            throw new PlatformNotSupportedException($"SecReview needs {WindowsProbes.MinimumWindowsName} or later.");
        }

        return new Scanner(WindowsProbes.Create(), TimeProvider.System)
            .RunAsync(CheckSelection.All, WindowsProbes.IsProcessElevated());
    }

    private void Show(ScanResult scan)
    {
        Checks.Clear();
        foreach (ScannedCheck check in ScanPresentation.InDisplayOrder(scan))
        {
            Checks.Add(new CheckItem(check));
        }

        Headline = ScanPresentation.Headline(scan);
        Detail = string.Create(
            CultureInfo.CurrentCulture,
            $"{ScanPresentation.Counts(scan)} · checked at {scan.FinishedAt.ToLocalTime():t}");
    }

    private bool Set<T>(ref T field, T value, string name)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return false;
        }

        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        return true;
    }
}
