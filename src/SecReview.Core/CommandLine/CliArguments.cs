namespace SecReview.CommandLine;

/// <summary>
/// Parses SecReviewCli's arguments. Deliberately strict: exactly one known command with exactly
/// the arguments it takes, because some commands run elevated and must not accept anything
/// unexpected.
/// </summary>
public static class CliArguments
{
    public const string Usage = """
        Usage: SecReviewCli <command>

          --report <file>   Run the checks and write the results to <file> as JSON.
          --diagnose        Show which readings work on this PC (for support).
          --version         Print the version.
          --help            Print this text.
        """;

    public static CliCommand Parse(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);

        if (args.Count == 0)
        {
            return new HelpCommand();
        }

        return args[0] switch
        {
            "--help" or "-h" or "/?" => WithoutArguments(args, new HelpCommand()),
            "--version" => WithoutArguments(args, new VersionCommand()),
            "--diagnose" => WithoutArguments(args, new DiagnoseCommand()),
            "--report" => Report(args),
            _ => new InvalidCommand($"Unknown command '{Printable(args[0])}'."),
        };
    }

    private static CliCommand WithoutArguments(IReadOnlyList<string> args, CliCommand command) =>
        args.Count > 1 ? new InvalidCommand($"Unexpected argument '{Printable(args[1])}'.") : command;

    private static CliCommand Report(IReadOnlyList<string> args)
    {
        if (args.Count < 2 || string.IsNullOrWhiteSpace(args[1]))
        {
            return new InvalidCommand("--report needs the file to write.");
        }

        if (args.Count > 2)
        {
            return new InvalidCommand($"Unexpected argument '{Printable(args[2])}'.");
        }

        // A file name starting with "--" is almost certainly a mistyped switch.
        if (args[1].StartsWith("--", StringComparison.Ordinal))
        {
            return new InvalidCommand("--report needs the file to write.");
        }

        return new ReportCommand(args[1]);
    }

    /// <summary>
    /// Keeps an echoed argument short and limited to printable ASCII. Everything else becomes
    /// '?': control and escape characters, but also Unicode format characters (such as
    /// right-to-left overrides), line separators and half surrogate pairs, which could reorder
    /// or split the message.
    /// </summary>
    private static string Printable(string argument)
    {
        const int MaxLength = 40;
        ReadOnlySpan<char> text = argument.AsSpan(0, Math.Min(argument.Length, MaxLength));
        Span<char> buffer = stackalloc char[MaxLength];
        for (int i = 0; i < text.Length; i++)
        {
            buffer[i] = text[i] is >= ' ' and <= '~' ? text[i] : '?';
        }

        string shown = new(buffer[..text.Length]);
        return argument.Length > MaxLength ? shown + "..." : shown;
    }
}
