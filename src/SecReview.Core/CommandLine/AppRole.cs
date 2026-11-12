namespace SecReview.CommandLine;

/// <summary>What the command line asked SecReview.exe (the windowed app) to be.</summary>
public abstract record AppRole;

/// <summary>Show the window.</summary>
/// <param name="SmokeTest">Close the window once it has drawn (used by the build).</param>
/// <param name="Demo">Show made-up results instead of scanning this PC.</param>
/// <param name="ScreenshotPath">Save a picture of the window to this PNG file, then close.</param>
public sealed record UiRole(bool SmokeTest = false, bool Demo = false, string? ScreenshotPath = null) : AppRole;

/// <summary>The arguments were not understood (unknown, repeated or incomplete).</summary>
public sealed record InvalidRole : AppRole;
