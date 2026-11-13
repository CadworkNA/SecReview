namespace SecReview.CommandLine;

/// <summary>What the command line asked SecReview.exe (the windowed app) to be.</summary>
public abstract record AppRole;

/// <summary>Show the window.</summary>
/// <param name="SmokeTest">Close the window once it has drawn (used by the build).</param>
/// <param name="Demo">Show made-up results instead of scanning this PC.</param>
/// <param name="ScreenshotPath">Save a picture of the window to this PNG file, then close.</param>
/// <param name="DemoState">Which state of the window the made-up results show.</param>
/// <param name="ShowCheck">The check to open the window on; null for the window as it is.</param>
public sealed record UiRole(
    bool SmokeTest = false,
    bool Demo = false,
    string? ScreenshotPath = null,
    Scanning.DemoState DemoState = Scanning.DemoState.Mixed,
    string? ShowCheck = null) : AppRole;

/// <summary>
/// Be the notification-area icon: run the checks again when they are due and say so when one
/// starts failing. No window; "Open" on the icon starts one.
/// </summary>
/// <param name="SmokeTest">Show the icon, run the checks once, exit (used by the build).</param>
public sealed record TrayRole(bool SmokeTest = false) : AppRole;

/// <summary>
/// One of SecReview's notifications was clicked: take the click from Windows, then open the
/// window on what it asks for. Nothing comes from the command line.
/// </summary>
public sealed record NotificationClickRole : AppRole;

/// <summary>
/// Write what error reports would hold to a file, without sending anything, and exit. Used by
/// the build to prove that no name, path or secret gets into a report.
/// </summary>
/// <param name="OutputPath">The file to write.</param>
public sealed record ErrorReportTestRole(string OutputPath) : AppRole;

/// <summary>The arguments were not understood (unknown, repeated or incomplete).</summary>
public sealed record InvalidRole : AppRole;
