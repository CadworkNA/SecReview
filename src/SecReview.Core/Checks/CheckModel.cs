namespace SecReview.Checks;

/// <summary>How a check ended.</summary>
public enum CheckStatus
{
    /// <summary>
    /// The check could not determine the answer; the summary says why. This is the zero value
    /// on purpose: a result nobody filled in reads as "could not check", never as a pass.
    /// </summary>
    Error = 0,

    Pass,

    Fail,

    /// <summary>The answer needs administrator rights and has not been read elevated yet.</summary>
    NeedsAdmin,

    /// <summary>The check does not apply to this PC (edition, hardware, software not installed).</summary>
    NotApplicable,
}

public enum Severity
{
    /// <summary>Worth knowing; never counts as failing.</summary>
    Info,
    Low,
    Medium,
    High,
}

public enum CheckCategory
{
    Access,
    Updates,
    FirewallAndSharing,
    SystemIntegrity,
    Hardening,
    SupplyChain,
}

/// <summary>Whether a check needs administrator rights.</summary>
public enum AdminNeed
{
    /// <summary>Fully answered as a normal user.</summary>
    No,

    /// <summary>Answered as a normal user; an elevated scan adds detail.</summary>
    ForFullDetail,

    /// <summary>Only answered by an elevated scan.</summary>
    Yes,
}

/// <summary>Whose settings a check reads.</summary>
public enum CheckScope
{
    /// <summary>The PC as a whole. May run elevated.</summary>
    Machine,

    /// <summary>
    /// The signed-in user's own settings and files. Never runs elevated: under another
    /// administrator's credentials it would read the wrong user's settings.
    /// </summary>
    User,
}

/// <summary>What one finding says about the item it describes.</summary>
public enum FindingStatus
{
    /// <summary>As expected.</summary>
    Ok,

    /// <summary>Not as expected; this is (part of) why the check fails.</summary>
    Problem,

    /// <summary>Context that is neither right nor wrong.</summary>
    Note,
}

/// <summary>One row of a check's "found versus expected" table.</summary>
/// <param name="Item">What the row is about, for example "Public network".</param>
/// <param name="Found">The value found, in words, for example "Off".</param>
/// <param name="Expected">The value expected, for example "On"; empty for a note.</param>
/// <param name="Status">Whether the row is fine, a problem, or a note.</param>
/// <param name="Source">Where the value came from (a registry path, a file and line), if useful.</param>
public sealed record Finding(string Item, string Found, string Expected, FindingStatus Status, string? Source = null)
{
    public static Finding Ok(string item, string found, string expected, string? source = null) =>
        new(item, found, expected, FindingStatus.Ok, source);

    public static Finding Problem(string item, string found, string expected, string? source = null) =>
        new(item, found, expected, FindingStatus.Problem, source);

    public static Finding Note(string item, string found, string? source = null) =>
        new(item, found, string.Empty, FindingStatus.Note, source);
}

/// <summary>What a check returns: the verdict, one line saying why, and the evidence.</summary>
/// <param name="Status">The verdict.</param>
/// <param name="Summary">One line saying why, for example "Firewall is off for the Public network".</param>
/// <param name="Findings">The evidence, as found-versus-expected rows.</param>
/// <param name="ManagedByPolicy">
/// True when the setting comes from an organisation's policy, so the user cannot change it and
/// the guidance is to contact IT.
/// </param>
public sealed record CheckOutcome(
    CheckStatus Status,
    string Summary,
    IReadOnlyList<Finding> Findings,
    bool ManagedByPolicy = false)
{
    public static CheckOutcome Pass(string summary, params IReadOnlyList<Finding> findings) =>
        new(CheckStatus.Pass, summary, findings);

    public static CheckOutcome Fail(string summary, params IReadOnlyList<Finding> findings) =>
        new(CheckStatus.Fail, summary, findings);

    public static CheckOutcome NeedsAdmin(string summary, params IReadOnlyList<Finding> findings) =>
        new(CheckStatus.NeedsAdmin, summary, findings);

    public static CheckOutcome NotApplicable(string summary) => new(CheckStatus.NotApplicable, summary, []);

    public static CheckOutcome Error(string summary, params IReadOnlyList<Finding> findings) =>
        new(CheckStatus.Error, summary, findings);
}

/// <summary>A check's outcome, stamped by the runner with when and how it was obtained.</summary>
/// <param name="CheckId">The check's stable identifier.</param>
/// <param name="Outcome">What the check returned.</param>
/// <param name="CheckedAt">When the check finished.</param>
/// <param name="Elevated">Whether it ran with administrator rights.</param>
/// <param name="Duration">How long it took.</param>
public sealed record CheckResult(
    string CheckId,
    CheckOutcome Outcome,
    DateTimeOffset CheckedAt,
    bool Elevated,
    TimeSpan Duration);
