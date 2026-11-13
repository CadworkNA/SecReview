using System.Text.RegularExpressions;
using SecReview.Checks;

namespace SecReview.Updates;

/// <summary>
/// Turns a release's notes into the plain lines shown under "What's new". The notes are the
/// list GitHub makes from the merged pull requests ("* feat: title by @author in address").
/// What a user wants from it is what is new and what was fixed: headings, authors, addresses
/// and changes that only matter to people who build SecReview are left out.
/// </summary>
internal static partial class ReleaseNotes
{
    /// <summary>Pull request prefixes (see CONTRIBUTING.md) for changes a user does not see.</summary>
    private static readonly string[] NotForUsers = ["docs", "test", "refactor", "build", "ci", "chore"];

    /// <summary>The notes as plain lines, one change each; empty when nothing in them is for users.</summary>
    public static string Plain(string? notes)
    {
        if (string.IsNullOrWhiteSpace(notes))
        {
            return string.Empty;
        }

        var lines = new List<string>();
        foreach (string raw in notes.Split('\n'))
        {
            string line = raw.Trim();
            if (line.Length == 0 || line[0] == '#' ||
                line.StartsWith("**Full Changelog**", StringComparison.OrdinalIgnoreCase) ||
                line.Contains(" made their first contribution in ", StringComparison.Ordinal))
            {
                continue;
            }

            if (line.StartsWith("* ", StringComparison.Ordinal) || line.StartsWith("- ", StringComparison.Ordinal))
            {
                line = line[2..].TrimStart();
            }

            Match change;
            try
            {
                line = Credit().Replace(line, string.Empty).TrimEnd();
                change = Prefix().Match(line);
            }
            catch (RegexMatchTimeoutException)
            {
                continue; // A line made to be slow to read is not a change worth showing.
            }

            if (!change.Success)
            {
                if (line.Length > 0)
                {
                    lines.Add(line);
                }

                continue;
            }

            string type = change.Groups["type"].Value;
            string text = Wording.UpperFirst(change.Groups["text"].Value);
            if (type == "feat")
            {
                lines.Add($"New: {text}");
            }
            else if (type == "fix")
            {
                lines.Add($"Fixed: {text}");
            }
            else if (!NotForUsers.Contains(type, StringComparer.Ordinal))
            {
                lines.Add(line);
            }
        }

        return string.Join('\n', lines);
    }

    /// <summary>" by @author in https://…/pull/12" at the end of a generated line, and a bare " (#12)".</summary>
    [GeneratedRegex(@"(\s+by @[A-Za-z0-9-]+(\[bot\])?\s+in\s+https://\S+|\s+\(#\d+\))$", RegexOptions.CultureInvariant, 250)]
    private static partial Regex Credit();

    /// <summary>"feat: text", "fix(scope): text", "feat!: text".</summary>
    [GeneratedRegex(@"^(?<type>[a-z]+)(\([^)]{0,40}\))?!?:\s*(?<text>\S.*)$", RegexOptions.CultureInvariant, 250)]
    private static partial Regex Prefix();
}
