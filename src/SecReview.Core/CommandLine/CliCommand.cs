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

/// <summary>
/// Run the checks that need administrator rights and send their results down the pipe
/// <see cref="PipeName"/>. Started by the app through the Windows prompt; the pipe name is the
/// only thing it is told.
/// </summary>
public sealed record ElevatedScanCommand(string PipeName) : CliCommand;

/// <summary>
/// Install the newest version of SecReview and report on the pipe <see cref="PipeName"/>.
/// Started by the app through the Windows prompt; the pipe name is the only thing it is told.
/// Which version, from where, and whether to trust it, it finds out itself.
/// </summary>
public sealed record ApplyUpdateCommand(string PipeName) : CliCommand;

/// <summary>The arguments were not understood; <see cref="Message"/> says why.</summary>
public sealed record InvalidCommand(string Message) : CliCommand;
