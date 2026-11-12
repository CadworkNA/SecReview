using SecReview.Checks;
using SecReview.Scanning;

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

    public string Source { get; }

    public bool IsOk { get; }

    public bool IsProblem { get; }

    public bool IsNote { get; }

    public string Description { get; }
}

/// <summary>One check as a row in the window.</summary>
public sealed partial class CheckItem
{
    public CheckItem(ScannedCheck check)
    {
        ArgumentNullException.ThrowIfNull(check);

        CheckOutcome outcome = check.Result.Outcome;
        Standing = ScanPresentation.StandingOf(check);

        Id = check.Definition.Id;
        Title = check.Title;
        Summary = outcome.Summary;
        Findings = outcome.Findings.Select(object (f) => new FindingRow(f)).ToList();
        Why = check.Text.Why;
        FixSteps = check.Text.Fix.Select(object (step, index) => $"{index + 1}. {step}").ToList();
        FixHeading = $"How to fix (about {check.Text.TimeToFix})";
        SettingsLink = check.Text.SettingsLink;

        StatusText = Standing switch
        {
            Standing.Passed => "Passed",
            Standing.NeedsAttention => "Needs attention",
            Standing.WorthKnowing => "Worth knowing",
            Standing.NeedsAdmin => "Needs administrator rights",
            Standing.DoesNotApply => "Does not apply to this PC",
            _ => "Could not be checked",
        };

        // Shown only where there is something for the user to do.
        ShowFix = Standing is Standing.NeedsAttention or Standing.WorthKnowing;
        ShowSettingsLink = ShowFix && SettingsLink is not null;

        // A check that needs attention starts open, so the reason is visible without a click.
        // Something only worth knowing stays closed, like everything else the headline leaves out.
        IsExpanded = Standing == Standing.NeedsAttention;

        Description = $"{Title}. {StatusText}. {Summary}";
    }

    public string Id { get; }

    /// <summary>Where the check stands; the same answer the headline and the order use.</summary>
    public Standing Standing { get; }

    public string Title { get; }

    public string Summary { get; }

    public string StatusText { get; }

    /// <summary>The rows (<see cref="FindingRow"/>). Typed as objects because the list controls only accept that.</summary>
    public List<object> Findings { get; }

    public bool HasFindings => Findings.Count > 0;

    public string Why { get; }

    public string FixHeading { get; }

    /// <summary>The numbered steps (strings), typed as objects for the same reason.</summary>
    public List<object> FixSteps { get; }

    public string? SettingsLink { get; }

    public bool ShowFix { get; }

    public bool ShowSettingsLink { get; }

    public bool IsExpanded { get; set; }

    public string Description { get; }

    public bool IsPass => Standing == Standing.Passed;

    public bool IsFail => Standing == Standing.NeedsAttention;

    public bool IsWorthKnowing => Standing == Standing.WorthKnowing;

    public bool IsNeedsAdmin => Standing == Standing.NeedsAdmin;

    public bool IsNotApplicable => Standing == Standing.DoesNotApply;

    public bool IsError => Standing == Standing.CouldNotCheck;
}
