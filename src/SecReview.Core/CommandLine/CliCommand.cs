namespace SecReview.CommandLine;

/// <summary>What the command line asked SecReviewCli to do.</summary>
public abstract record CliCommand;

/// <summary>Print the usage text.</summary>
public sealed record HelpCommand : CliCommand;

/// <summary>Print the version.</summary>
public sealed record VersionCommand : CliCommand;

/// <summary>Run every probe once and print which work on this PC.</summary>
public sealed record DiagnoseCommand : CliCommand;

/// <summary>Run the checks and write the results to <see cref="Path"/> as JSON.</summary>
public sealed record ReportCommand(string Path) : CliCommand;

/// <summary>The arguments were not understood; <see cref="Message"/> says why.</summary>
public sealed record InvalidCommand(string Message) : CliCommand;
