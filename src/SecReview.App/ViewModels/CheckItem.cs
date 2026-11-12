using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using SecReview.Checks;
using SecReview.Scanning;
using SecReview.Settings;

namespace SecReview.App.ViewModels;

/// <summary>One row of a check's "found versus expected" table.</summary>
public sealed partial class FindingRow
{
    public FindingRow(Finding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);

        Item = finding.Item;
        Found = finding.Found;
        Expected = finding.Expected;
        Source = finding.Source ?? string.Empty;
        HasSource = Source.Length > 0;
        IsOk = finding.Status == FindingStatus.Ok;
        IsProblem = finding.Status == FindingStatus.Problem;
        IsNote = finding.Status == FindingStatus.Note;

        // What a screen reader says for the whole row.
        Description = finding.Status switch
        {
            FindingStatus.Ok => $"{Item}: {Found}, as expected.",
            FindingStatus.Problem => $"{Item}: {Found}. Expected {Expected}.",
            _ => $"{Item}: {Found}.",
        };
    }

    public string Item { get; }

    public string Found { get; }

    public string Expected { get; }

    /// <summary>Where the value was read (a registry key, a file and line); empty when the check does not say.</summary>
    public string Source { get; }

    public bool HasSource { get; }

    public bool IsOk { get; }

    public bool IsProblem { get; }

    public bool IsNote { get; }

    public string Description { get; }
}

/// <summary>
/// A group of rows under one heading. It stays the same object while its rows and the words
/// beside its title change, so the window only redraws what is new.
/// </summary>
public sealed partial class SectionItem(string title) : INotifyPropertyChanged
{
    private string _detail = string.Empty;

    public event PropertyChangedEventHandler? PropertyChanged;

    public string Title { get; } = title;

    /// <summary>A few words beside the title, for example "7 of 8 pass".</summary>
    public string Detail
    {
        get => _detail;
        set
        {
            if (_detail != value)
            {
                _detail = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Detail)));
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Description)));
            }
        }
    }

    /// <summary>The rows (<see cref="CheckItem"/>). Typed as objects because the list controls only accept that.</summary>
    public ObservableCollection<object> Checks { get; } = [];

    /// <summary>What a screen reader says for the heading.</summary>
    public string Description => Detail.Length > 0 ? $"{Title}, {Detail}" : Title;
}

/// <summary>An ignored check as a line in the settings dialog.</summary>
public sealed partial class IgnoredRow(string id, string title, string reason)
{
    public string Id { get; } = id;

    public string Title { get; } = title;

    public string Reason { get; } = reason;
}

/// <summary>One check as a row in the window.</summary>
public sealed partial class CheckItem
{
    public CheckItem(ScannedCheck check, IgnoredCheck? ignored, bool isExpanded, bool isBeingChecked)
    {
        ArgumentNullException.ThrowIfNull(check);

        Check = check;
        Ignored = ignored;

        CheckOutcome outcome = check.Result.Outcome;
        Standing found = ScanPresentation.StandingOf(check);
        Standing = ignored is null ? found : Standing.Ignored;

        Id = check.Definition.Id;
        Title = check.Title;
        Summary = outcome.Summary;
        Findings = outcome.Findings.Select(object (f) => new FindingRow(f)).ToList();
        Why = check.Text.Why;
        SettingsLink = check.Text.SettingsLink;
        IsExpanded = isExpanded;
        IsBeingChecked = isBeingChecked;

        // A failure says how much it matters; nothing else needs a severity.
        SeverityText = found == Standing.NeedsAttention ? check.Definition.Severity.ToString() : string.Empty;

        string status = ScanPresentation.StandingName(found);
        StatusText = string.Create(
            CultureInfo.CurrentCulture,
            $"{status}{(SeverityText.Length > 0 ? $" · {SeverityText}" : string.Empty)} · {ScanPresentation.CategoryName(check.Definition.Category)} · checked {check.Result.CheckedAt.ToLocalTime():d MMM yyyy, HH:mm}");

        IsIgnored = ignored is not null;
        IgnoredText = ignored is null
            ? string.Empty
            : ignored.Reason.Length > 0 ? $"Ignored: {ignored.Reason}" : "Ignored, no reason given.";

        // Shown only where there is something for the user to do. A setting an organisation
        // manages cannot be changed by the user, so the steps give way to "contact IT".
        bool somethingToDo = found is Standing.NeedsAttention or Standing.WorthKnowing;
        IsManaged = outcome.ManagedByPolicy;
        ShowFix = somethingToDo && !IsManaged;
        ShowManaged = somethingToDo && IsManaged;
        FixSteps = check.Text.Fix.Select(object (step, index) => $"{index + 1}. {step}").ToList();
        FixHeading = $"How to fix (about {check.Text.TimeToFix})";
        ShowSettingsLink = ShowFix && SettingsLink is not null;

        // Only a failing check can be ignored: there is nothing to leave out of the count otherwise.
        CanIgnore = !IsIgnored && found is Standing.NeedsAttention or Standing.WorthKnowing or Standing.CouldNotCheck;

        Description = IsIgnored
            ? $"{Title}. Ignored. {status}. {Summary}"
            : SeverityText.Length > 0 ? $"{Title}. {status}, {SeverityText}. {Summary}" : $"{Title}. {status}. {Summary}";
    }

    public string Id { get; }

    /// <summary>The result this row was made from.</summary>
    public ScannedCheck Check { get; }

    /// <summary>The ignore entry this row was made with; null when the check is not ignored.</summary>
    public IgnoredCheck? Ignored { get; }

    /// <summary>Whether this row still says everything about that result, so it can stay on screen as it is.</summary>
    public bool IsStill(ScannedCheck check, IgnoredCheck? ignored, bool isBeingChecked) =>
        ReferenceEquals(Check, check) && Equals(Ignored, ignored) && IsBeingChecked == isBeingChecked;

    /// <summary>Where the check stands; the same answer the headline and the order use.</summary>
    public Standing Standing { get; }

    public string Title { get; }

    public string Summary { get; }

    public string StatusText { get; }

    public string SeverityText { get; }

    public bool ShowSeverity => SeverityText.Length > 0 && !IsIgnored;

    /// <summary>The rows (<see cref="FindingRow"/>). Typed as objects because the list controls only accept that.</summary>
    public List<object> Findings { get; }

    public bool HasFindings => Findings.Count > 0;

    public string Why { get; }

    public string FixHeading { get; }

    /// <summary>The numbered steps (strings), typed as objects for the same reason.</summary>
    public List<object> FixSteps { get; }

    public string? SettingsLink { get; }

    public bool ShowFix { get; }

    public bool IsManaged { get; }

    public bool ShowManaged { get; }

    public bool ShowSettingsLink { get; }

    public bool IsIgnored { get; }

    public string IgnoredText { get; }

    public bool CanIgnore { get; }

    /// <summary>Whether this one check is being run again right now.</summary>
    public bool IsBeingChecked { get; }

    public bool CanCheckAgain => !IsBeingChecked;

    public bool IsExpanded { get; set; }

    public string Description { get; }

    /// <summary>What a screen reader says for each button, so that twenty "Check again" buttons can be told apart.</summary>
    public string CheckAgainName => $"Check again: {Title}";

    public string CopyName => $"Copy details: {Title}";

    public string IgnoreName => $"Ignore: {Title}";

    public string StopIgnoringName => $"Stop ignoring: {Title}";

    public string OpenSettingsName => $"Open Settings for: {Title}";

    public bool IsPass => Standing == Standing.Passed;

    public bool IsFail => Standing == Standing.NeedsAttention;

    public bool IsWorthKnowing => Standing == Standing.WorthKnowing;

    public bool IsNeedsAdmin => Standing == Standing.NeedsAdmin;

    public bool IsNotApplicable => Standing == Standing.DoesNotApply;

    public bool IsError => Standing == Standing.CouldNotCheck;

    public bool IsIgnoredIcon => Standing == Standing.Ignored;
}
