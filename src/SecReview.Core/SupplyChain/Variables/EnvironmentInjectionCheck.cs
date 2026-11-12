using SecReview.Checks;

namespace SecReview.SupplyChain.Variables;

/// <summary>
/// No permanent environment variable should make a whole toolchain load extra code every time
/// it starts: Node.js preloads, .NET start-up hooks and profilers, Java agents, a script that
/// every Bash script runs first. Malware sets these to stay on a developer's PC; so do a few
/// legitimate tools, which is why each is named rather than judged by its value. Variables
/// that are common and milder (extra Python folders, a Rust compiler wrapper, Git helper
/// programs) are listed without failing. Values are not shown.
/// </summary>
public sealed class EnvironmentInjectionCheck : ICheck
{
    public const string Id = "sc.env.injection";

    private const string Expected = "Not set";

    /// <summary>Variables that are a finding whenever they are set.</summary>
    private static readonly (string Name, string Item, string Found)[] Always =
    [
        ("DOTNET_STARTUP_HOOKS", ".NET start-up hooks", "Load code into every .NET program"),
        ("BASH_ENV", "Bash start-up script", "Runs before every Bash script"),
    ];

    /// <summary>Variables that are a finding when their value asks for code to be loaded.</summary>
    private static readonly (string Name, string[] Markers, string Item, string Found)[] WhenTheyLoadCode =
    [
        ("NODE_OPTIONS", ["--require", "-r", "--import", "--loader", "--experimental-loader"], "Node.js start-up options", "Load code into every Node.js program"),
        ("JAVA_TOOL_OPTIONS", ["-javaagent:", "-agentpath:", "-agentlib:"], "Java start-up options", "Load an agent into every Java program"),
        ("JDK_JAVA_OPTIONS", ["-javaagent:", "-agentpath:", "-agentlib:"], "Java start-up options", "Load an agent into every Java program"),
        ("_JAVA_OPTIONS", ["-javaagent:", "-agentpath:", "-agentlib:"], "Java start-up options", "Load an agent into every Java program"),
        ("PERL5OPT", ["-M", "-m"], "Perl start-up options", "Load a module into every Perl program"),
        ("RUBYOPT", ["-r"], "Ruby start-up options", "Load a library into every Ruby program"),
    ];

    /// <summary>A profiler is loaded only when both the switch and the profiler's id are set.</summary>
    private static readonly (string Switch, string Profiler, string Item)[] Profilers =
    [
        ("CORECLR_ENABLE_PROFILING", "CORECLR_PROFILER", ".NET profiler"),
        ("COR_ENABLE_PROFILING", "COR_PROFILER", ".NET Framework profiler"),
    ];

    /// <summary>Variables worth knowing about that many developers set on purpose.</summary>
    private static readonly (string Name, string Item, string Found)[] Notes =
    [
        ("PYTHONPATH", "Extra Python folders", "Every Python program loads code from them"),
        ("PYTHONSTARTUP", "Python start-up script", "Runs when Python starts interactively"),
        ("RUSTC_WRAPPER", "Rust compiler wrapper", "A program runs around every Rust compile"),
        ("RUSTC_WORKSPACE_WRAPPER", "Rust compiler wrapper", "A program runs around every Rust compile"),
        ("GIT_SSH_COMMAND", "Git connection program", "Git runs it to connect over SSH"),
        ("GIT_ASKPASS", "Git password program", "Git runs it to ask for passwords"),
    ];

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.Medium, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (PersistentVariables.Load(context.Probes, out IReadOnlyList<PersistentVariable> variables) is { } failed)
        {
            return failed;
        }

        var problems = new List<Finding>();
        foreach ((string name, string item, string found) in Always)
        {
            if (variables.Find(name) is { } variable)
            {
                problems.Add(Finding.Problem($"{item} ({name})", found, Expected, variable.Source));
            }
        }

        foreach ((string name, string[] markers, string item, string found) in WhenTheyLoadCode)
        {
            if (variables.Find(name) is { } variable && LoadsCode(variable.Value, markers))
            {
                problems.Add(Finding.Problem($"{item} ({name})", found, "No code loaded", variable.Source));
            }
        }

        foreach ((string enabled, string profiler, string item) in Profilers)
        {
            if (variables.Find(enabled) is { } on && IsSwitchedOn(on.Value) && variables.Find(profiler) is { } which)
            {
                problems.Add(Finding.Problem($"{item} ({profiler})", "Loaded into every program of that kind", Expected, which.Source));
            }
        }

        // Java reads "@file" in JDK_JAVA_OPTIONS as more options from that file, which may load an agent.
        if (variables.Find("JDK_JAVA_OPTIONS") is { } java && java.Value.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries).Any(w => w.StartsWith('@')) &&
            !LoadsCode(java.Value, ["-javaagent:", "-agentpath:", "-agentlib:"]))
        {
            problems.Add(Finding.Problem(
                "Java start-up options (JDK_JAVA_OPTIONS)", "Take more options from a file, which may load an agent", "No options file", java.Source));
        }

        var notes = new List<Finding>();
        foreach ((string name, string item, string found) in Notes)
        {
            if (variables.Find(name) is { } variable)
            {
                notes.Add(Finding.Note($"{item} ({name})", found, variable.Source));
            }
        }

        if (problems.Count > 0)
        {
            return CheckOutcome.Fail(
                problems.Count == 1
                    ? $"A permanent variable loads code into every program of one kind: {VariableOf(problems[0])}."
                    : $"{problems.Count} permanent variables load code into every program of one kind.",
                [.. problems, .. notes]);
        }

        if (notes.Count > 0)
        {
            return CheckOutcome.Pass(
                notes.Count == 1
                    ? "No variable loads code into your tools; 1 changes how a tool starts."
                    : $"No variable loads code into your tools; {notes.Count} change how tools start.",
                [Finding.Ok("Variables that load code into every program", "None", "None"), .. notes]);
        }

        return CheckOutcome.Pass(
            "No permanent variable loads code into your development tools.",
            Finding.Ok("Variables that load code into every program", "None", "None"));
    }

    /// <summary>
    /// Whether an options text contains one of the markers, as an option of its own
    /// ("--require x", "--require=x") or as the start of one ("-javaagent:x", "-rfoo").
    /// </summary>
    internal static bool LoadsCode(string options, string[] markers)
    {
        foreach (string token in options.Split([' ', '\t', '"', '\''], StringSplitOptions.RemoveEmptyEntries))
        {
            foreach (string marker in markers)
            {
                bool longOption = marker.StartsWith("--", StringComparison.Ordinal);
                bool matches = longOption
                    ? token.Equals(marker, StringComparison.Ordinal) || token.StartsWith(marker + "=", StringComparison.Ordinal)
                    : token.StartsWith(marker, StringComparison.Ordinal);
                if (matches)
                {
                    return true;
                }
            }
        }

        return false;
    }

    /// <summary>
    /// Whether a profiling switch is on. The runtime reads it as a hexadecimal number and takes
    /// anything but zero as on, so "01" and "0x1" count as much as "1".
    /// </summary>
    internal static bool IsSwitchedOn(string value)
    {
        string digits = value.Trim();
        if (digits.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            digits = digits[2..];
        }

        return digits.Length is > 0 and <= 16 && digits.All(char.IsAsciiHexDigit) && digits.Any(c => c != '0');
    }

    /// <summary>The variable's name from an item written as "What it is (NAME)".</summary>
    private static string VariableOf(Finding problem) => problem.Item[(problem.Item.LastIndexOf('(') + 1)..].TrimEnd(')');
}
