namespace SecReview.CommandLine;

/// <summary>What the command line asked SecReview.exe (the windowed app) to be.</summary>
public abstract record AppRole;

/// <summary>Show the window. <see cref="SmokeTest"/>: close it once it has drawn.</summary>
public sealed record UiRole(bool SmokeTest = false) : AppRole;

/// <summary>The arguments were not understood (unknown or repeated).</summary>
public sealed record InvalidRole : AppRole;
