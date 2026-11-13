using System.Globalization;

namespace SecReview.Checks.BuiltIn.Programs;

/// <summary>
/// Gathers what a check found for each entry of a list (services, start-up programs, rules)
/// and turns it into one honest outcome:
/// a problem anywhere fails; with no problem, an entry that could not be read is "needs
/// administrator" or "could not check", never a pass; only a list read in full passes.
/// </summary>
/// <param name="one">What one entry is called: "service program".</param>
/// <param name="many">The same for several: "service programs".</param>
/// <param name="elevated">Whether this run has administrator rights.</param>
internal sealed class EntryReport(string one, string many, bool elevated)
{
    /// <summary>The most rows of one kind a result shows; the rest are counted.</summary>
    public const int Most = 10;

    public const string Expected = "Only administrators can change it";

    private readonly List<Finding> _problems = [];
    private readonly List<Finding> _notes = [];
    private readonly List<Finding> _unread = [];
    private int _fine;
    private int _problemEntries;
    private bool _unreadForAnotherReason;
    private string? _firstReason;

    /// <summary>Set when a problem comes from a setting the organisation's policy made.</summary>
    public bool ManagedByPolicy { get; set; }

    public int Problems => _problemEntries;

    /// <summary>An entry that is as it should be.</summary>
    public void Fine() => _fine++;

    public void Problem(string item, string found, string? source = null) => Problem(item, found, source, entries: 1);

    /// <summary>One row for several entries that have the same thing wrong: the summary counts them all.</summary>
    public void Problem(string item, string found, string? source, int entries)
    {
        _problems.Add(Finding.Problem(item, found, Expected, source));
        _problemEntries += entries;
    }

    /// <summary>Something worth showing that is neither right nor wrong.</summary>
    public void Note(string item, string found, string? source = null) => _notes.Add(Finding.Note(item, found, source));

    /// <summary>An entry that could not be judged.</summary>
    /// <param name="item">The entry.</param>
    /// <param name="found">Why, as shown in its row.</param>
    /// <param name="needsAdministrator">True when administrator rights are all that is missing.</param>
    /// <param name="source">Where the entry is stored.</param>
    public void Unread(string item, string found, bool needsAdministrator, string? source = null)
    {
        _unread.Add(Finding.Note(item, found, source));
        _firstReason ??= $"{item}: {Wording.LowerFirst(found)}";
        _unreadForAnotherReason |= !needsAdministrator || elevated;
    }

    /// <summary>One entry's judgement, put where it belongs.</summary>
    public void Add(string item, Verdict verdict, string? source = null)
    {
        if (verdict.IsProblem)
        {
            Problem(item, verdict.Found, source);
        }
        else if (verdict.Kind == VerdictKind.Unknown)
        {
            Unread(item, verdict.Found, verdict.NeedsAdministrator, source);
        }
        else if (verdict.Kind == VerdictKind.Missing)
        {
            // An entry left behind by something uninstalled: nothing runs, and nobody but an
            // administrator can make something run.
            _fine++;
            Note(item, verdict.Found, source);
        }
        else
        {
            Fine();
        }
    }

    /// <summary>One command's judgement, put where it belongs.</summary>
    public void Add(string item, CommandVerdict verdict, string? source = null)
    {
        if (verdict.IsProblem)
        {
            Problem(item, verdict.Found, source);
        }
        else if (verdict.Reference.PerUser)
        {
            _fine++;
            Note(item, "Each user's own copy; not judged", source);
        }
        else if (verdict.IsUnknown)
        {
            Unread(item, verdict.Found, verdict.NeedsAdministrator, source);
        }
        else
        {
            _fine++;
            if (verdict.IsMissing)
            {
                Note(item, verdict.Found, source);
            }
            else if (verdict.Reference.CommandOnly)
            {
                Note(item, "Runs a command line; only its first program was judged", source);
            }
        }
    }

    /// <summary>The outcome for everything added.</summary>
    /// <param name="none">The summary when the list is empty: "No program starts for every user."</param>
    public CheckOutcome Outcome(string none)
    {
        int total = _fine + _problemEntries + _unread.Count;
        var findings = new List<Finding>();
        Capped(findings, _problems, "More problems");

        if (_problems.Count > 0)
        {
            Capped(findings, [.. _unread, .. _notes], "More notes");
            string summary = _problemEntries == 1
                ? $"1 {one} is not protected from change: {_problems[0].Item}."
                : string.Create(CultureInfo.InvariantCulture, $"{_problemEntries} {many} are not protected from change.");
            return CheckOutcome.Fail(summary, findings) with { ManagedByPolicy = ManagedByPolicy };
        }

        Capped(findings, [.. _unread, .. _notes], "More notes");
        if (_unread.Count > 0)
        {
            string read = string.Create(CultureInfo.InvariantCulture, $"No problem in {_fine} {(_fine == 1 ? one : many)}");
            return _unreadForAnotherReason
                ? CheckOutcome.Error(string.Create(CultureInfo.InvariantCulture, $"{read}; {_unread.Count} could not be judged. {Wording.UpperFirst(_firstReason!)}."), findings)
                : CheckOutcome.NeedsAdmin(
                    string.Create(CultureInfo.InvariantCulture, $"{read}; {_unread.Count} more {(_unread.Count == 1 ? "needs" : "need")} administrator rights to read."),
                    findings);
        }

        if (total == 0)
        {
            return CheckOutcome.Pass(none, [Finding.Ok(Wording.UpperFirst(many), "None", Expected), .. findings]);
        }

        findings.Insert(0, Finding.Ok(
            Wording.UpperFirst(many), string.Create(CultureInfo.InvariantCulture, $"{total} checked, all protected"), Expected));
        return CheckOutcome.Pass(
            total == 1
                ? $"The 1 {one} is protected from change by standard users."
                : string.Create(CultureInfo.InvariantCulture, $"All {total} {many} are protected from change by standard users."),
            findings);
    }

    private static void Capped(List<Finding> all, List<Finding> some, string more)
    {
        all.AddRange(some.Take(Most));
        if (some.Count > Most)
        {
            all.Add(Finding.Note(more, string.Create(CultureInfo.InvariantCulture, $"{some.Count - Most} more")));
        }
    }
}
