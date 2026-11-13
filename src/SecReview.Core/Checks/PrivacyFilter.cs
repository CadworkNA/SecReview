using System.Text.RegularExpressions;

namespace SecReview.Checks;

/// <summary>
/// Takes the user's and the computer's name out of result text. Error messages from Windows
/// often contain a path under the user's profile, and results end up in report files, logs and
/// error reports, which must say what is wrong with a PC without saying whose PC it is.
/// </summary>
public sealed partial class PrivacyFilter
{
    private const string ProfilePlaceholder = "%USERPROFILE%";
    private const string UserPlaceholder = "<user>";
    private const string ComputerPlaceholder = "<computer>";
    private const string AccountPlaceholder = "<account>";

    /// <summary>Names shorter than this are too likely to be ordinary words to replace on sight.</summary>
    private const int MinimumNameLength = 3;

    private static readonly TimeSpan MatchLimit = TimeSpan.FromSeconds(1);

    /// <summary>
    /// Account names that are also ordinary words in result text ("needs administrator rights").
    /// They are not replaced as bare words; a profile path that contains them still is.
    /// </summary>
    private static readonly HashSet<string> GenericNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "administrator", "admin", "user", "users", "guest", "owner", "default", "public", "system",
        "computer", "windows", "desktop", "laptop", "test", "dev",
    };

    private readonly bool _enabled;
    private readonly Regex? _profilePath;
    private readonly Regex? _userName;
    private readonly Regex? _computerName;

    public PrivacyFilter(string? userProfilePath, string? userName, string? computerName)
        : this(enabled: true, userProfilePath, userName, computerName)
    {
    }

    private PrivacyFilter(bool enabled, string? userProfilePath, string? userName, string? computerName)
    {
        _enabled = enabled;

        // Only the whole folder name: the profile "C:\Users\al" must not match the start of
        // "C:\Users\alice".
        _profilePath = string.IsNullOrWhiteSpace(userProfilePath)
            ? null
            : new Regex(
                Regex.Escape(userProfilePath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)) +
                    @"(?![\w.\-])",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
                MatchLimit);
        _userName = WholeWord(userName);
        _computerName = WholeWord(computerName);
    }

    /// <summary>A filter for the user and computer this process runs as and on.</summary>
    public static PrivacyFilter ForThisProcess() => new(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        Environment.UserName,
        Environment.MachineName);

    /// <summary>A filter that changes nothing at all (for tests that assert on exact text).</summary>
    public static PrivacyFilter None { get; } = new(enabled: false, null, null, null);

    public string Scrub(string text)
    {
        if (!_enabled || string.IsNullOrEmpty(text))
        {
            return text;
        }

        string result = text;
        if (_profilePath is not null)
        {
            result = _profilePath.Replace(result, ProfilePlaceholder);
        }

        // Any other "C:\Users\name" (another profile, or a differently spelled path).
        result = UsersFolder().Replace(result, match => $"{match.Groups[1].Value}{UserPlaceholder}");

        // An account's identifier names the PC or domain it belongs to and the account in it.
        // Windows puts them into the names of tasks and services made for one user.
        result = AccountIdentifier().Replace(result, AccountPlaceholder);

        if (_userName is not null)
        {
            result = _userName.Replace(result, UserPlaceholder);
        }

        if (_computerName is not null)
        {
            result = _computerName.Replace(result, ComputerPlaceholder);
        }

        return result;
    }

    public Finding Scrub(Finding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);
        return finding with
        {
            Item = Scrub(finding.Item),
            Found = Scrub(finding.Found),
            Expected = Scrub(finding.Expected),
            Source = finding.Source is null ? null : Scrub(finding.Source),
        };
    }

    public CheckOutcome Scrub(CheckOutcome outcome)
    {
        ArgumentNullException.ThrowIfNull(outcome);
        return outcome with
        {
            Summary = Scrub(outcome.Summary),
            Findings = [.. outcome.Findings.Select(Scrub)],
        };
    }

    /// <summary>
    /// Matches the name as a whole word, but not inside a placeholder this filter inserted
    /// ("&lt;user&gt;", "%USERPROFILE%"), and not at all when the name is an ordinary word.
    /// </summary>
    private static Regex? WholeWord(string? name)
    {
        string? trimmed = name?.Trim();
        if (string.IsNullOrEmpty(trimmed) || trimmed.Length < MinimumNameLength || GenericNames.Contains(trimmed))
        {
            return null;
        }

        return new Regex(
            $@"(?<![\w%<]){Regex.Escape(trimmed)}(?![\w%>])",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
            MatchLimit);
    }

    // The folder name after "X:\Users\". A name may contain spaces, but only when a backslash
    // follows it; otherwise it ends at the first space, so the words of a message that come
    // after an unquoted path are left alone.
    [GeneratedRegex(
        @"([A-Za-z]:\\Users\\)(?:[^\\/:*?""<>|\r\n]+(?=\\)|[^\\/:*?""<>|\r\n\s]+)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex UsersFolder();

    // "S-1-5-21-a-b-c-rid" (a PC's or domain's account) and "S-1-12-1-a-b-c-d" (a directory account).
    [GeneratedRegex(
        @"(?<![A-Za-z0-9])S-1-(?:5-21|12-1)(?:-\d{1,10}){3,5}",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex AccountIdentifier();
}
