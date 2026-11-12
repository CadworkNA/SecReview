using SecReview.Checks;
using SecReview.Probing;
using SecReview.SupplyChain.Scoop;

namespace SecReview.SupplyChain.Go;

/// <summary>
/// Go verifies every module it downloads against a public checksum database, over HTTPS.
/// Settings can switch that off: <c>GOINSECURE</c> (no TLS checks for matching modules),
/// <c>GOSUMDB=off</c>, a module proxy over plain HTTP, or an exemption pattern that matches
/// everything. Exemptions for a company's own modules (<c>GOPRIVATE</c>, <c>GONOSUMDB</c>)
/// are normal and are listed, not failed. Go has no wait for new releases; the checksum
/// database is what it relies on. Settings come from permanent variables, then Go's own
/// settings file (<c>go env -w</c> writes it).
/// </summary>
public sealed class GoSettingsCheck : ICheck
{
    public const string Id = "sc.go.settings";

    private static readonly string[] Names = ["GOINSECURE", "GOSUMDB", "GONOSUMDB", "GOPRIVATE", "GOPROXY"];

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.High, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        SystemProbes probes = context.Probes;

        ProbeResult<string> profile = probes.Environment.Folder(KnownFolder.UserProfile);
        ProbeResult<string> roaming = probes.Environment.Folder(KnownFolder.RoamingAppData);
        ProbeResult<string> programFiles = probes.Environment.Folder(KnownFolder.ProgramFiles);
        if (!profile.IsOk || !roaming.IsOk || !programFiles.IsOk)
        {
            return CheckOutcome.Error("Windows did not say where your user folders are.");
        }

        // Go's own settings file; GOENV moves it, and "off" means there is none.
        if (PersistentEnvironment.Read(probes, "GOENV", out string? moved, out _) is { } failed)
        {
            return failed;
        }

        string path = string.IsNullOrWhiteSpace(moved) ? $@"{roaming.Value}\go\env" : moved.Trim().Replace('/', '\\');
        var fromFile = new Dictionary<string, (string Value, int Line)>(StringComparer.Ordinal);
        bool fileExists = false;
        if (!path.Equals("off", StringComparison.OrdinalIgnoreCase))
        {
            ProbeResult<string> text = probes.Files.ReadText(path);
            if (text.IsOk)
            {
                fileExists = true;
                string[] lines = text.Value!.Split('\n');
                for (int i = 0; i < lines.Length; i++)
                {
                    string line = lines[i].Trim();
                    int equals = line.IndexOf('=', StringComparison.Ordinal);
                    if (equals > 0 && line[0] != '#')
                    {
                        fromFile[line[..equals].Trim()] = (line[(equals + 1)..].Trim(), i + 1);
                    }
                }
            }
            else if (text.Status != ProbeStatus.NotFound)
            {
                return CheckOutcome.Error("Go's settings file could not be read.");
            }
        }

        // A permanent variable wins over the file.
        var settings = new Dictionary<string, (string Value, string Source)>(StringComparer.Ordinal);
        bool anyVariable = !string.IsNullOrWhiteSpace(moved);
        foreach (string name in Names)
        {
            if (PersistentEnvironment.Read(probes, name, out string? value, out string? source) is { } unread)
            {
                return unread;
            }

            if (value is not null)
            {
                anyVariable = true;
                settings[name] = (value.Trim(), source!);
            }
            else if (fromFile.TryGetValue(name, out (string Value, int Line) written))
            {
                settings[name] = (written.Value, $"{path}, line {written.Line}");
            }
        }

        bool installed = fileExists || anyVariable ||
            SettingsFiles.FolderExists(probes.Files, $@"{programFiles.Value}\Go") ||
            SettingsFiles.FolderExists(probes.Files, $@"{profile.Value}\go") ||
            ScoopLocator.AppVersion(probes, "go") is not null;
        if (!installed)
        {
            return CheckOutcome.NotApplicable("Go is not installed.");
        }

        var problems = new List<Finding>();
        var notes = new List<Finding>();

        if (Patterns("GOINSECURE") is { Length: > 0 } insecure)
        {
            problems.Add(Finding.Problem(
                "Modules fetched without TLS checks", insecure.Length == 1 ? "1 pattern" : $"{insecure.Length} patterns", "None", settings["GOINSECURE"].Source));
        }

        if (settings.TryGetValue("GOSUMDB", out (string Value, string Source) sumdb) && sumdb.Value.Equals("off", StringComparison.OrdinalIgnoreCase))
        {
            problems.Add(Finding.Problem("Checksum database", "Off", "On", sumdb.Source));
        }

        foreach (string name in (string[])["GONOSUMDB", "GOPRIVATE"])
        {
            if (Patterns(name) is not { Length: > 0 } exempt)
            {
                continue;
            }

            if (exempt.Any(MatchesEveryHost))
            {
                problems.Add(Finding.Problem("Checksum database", $"Skipped for every module ({name})", "On", settings[name].Source));
            }
            else
            {
                notes.Add(Finding.Note(
                    $"Modules exempt from the checksum database ({name})", exempt.Length == 1 ? "1 pattern" : $"{exempt.Length} patterns", settings[name].Source));
            }
        }

        if (settings.TryGetValue("GOPROXY", out (string Value, string Source) proxy) &&
            proxy.Value.Split([',', '|'], StringSplitOptions.TrimEntries).Any(p => p.StartsWith("http://", StringComparison.OrdinalIgnoreCase)))
        {
            problems.Add(Finding.Problem("Module proxy", "Plain HTTP", "HTTPS", proxy.Source));
        }

        if (problems.Count > 0)
        {
            return CheckOutcome.Fail(
                problems.Count == 1
                    ? $"Go: {Wording.LowerFirst(problems[0].Item)}: {Wording.LowerFirst(problems[0].Found)}."
                    : $"Go has {problems.Count} settings that weaken how it verifies modules.",
                [.. problems, .. notes]);
        }

        return CheckOutcome.Pass(
            notes.Count == 0
                ? "Go verifies every module against the checksum database, over HTTPS."
                : "Go verifies modules over HTTPS; some are exempt from the checksum database, as private modules are.",
            [Finding.Ok("Checksum database", "On", "On"), Finding.Ok("Modules fetched without TLS checks", "None", "None"), .. notes]);

        string[]? Patterns(string name) => settings.TryGetValue(name, out (string Value, string Source) set)
            ? set.Value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            : null;
    }

    /// <summary>
    /// Whether a pattern exempts every module: its host part, a glob where "*" and "?" stand
    /// for characters other than "/", matches hosts that have nothing in common ("*", "*.*").
    /// </summary>
    internal static bool MatchesEveryHost(string pattern)
    {
        int slash = pattern.IndexOf('/', StringComparison.Ordinal);
        string host = slash < 0 ? pattern : pattern[..slash];
        return host.Length > 0 && Matches(host, "github.com") && Matches(host, "golang.org") && Matches(host, "example.net");
    }

    /// <summary>A small glob match: "*" is any run of characters, "?" any one character.</summary>
    private static bool Matches(ReadOnlySpan<char> pattern, ReadOnlySpan<char> text)
    {
        int p = 0;
        int t = 0;
        int star = -1;
        int resume = 0;
        while (t < text.Length)
        {
            if (p < pattern.Length && (pattern[p] == '?' || char.ToLowerInvariant(pattern[p]) == text[t]))
            {
                p++;
                t++;
            }
            else if (p < pattern.Length && pattern[p] == '*')
            {
                star = p++;
                resume = t;
            }
            else if (star >= 0)
            {
                p = star + 1;
                t = ++resume;
            }
            else
            {
                return false;
            }
        }

        while (p < pattern.Length && pattern[p] == '*')
        {
            p++;
        }

        return p == pattern.Length;
    }
}
