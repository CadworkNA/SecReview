namespace SecReview.CommandLine;

/// <summary>Parses SecReview.exe's arguments into the role the process takes.</summary>
public static class AppArguments
{
    /// <summary>Used by the build: load the window, draw it, exit 0.</summary>
    public const string SmokeTestSwitch = "--smoke-test";

    /// <summary>
    /// Show made-up results. May be followed by the state to show (<see cref="Scanning.DemoScan.StateNames"/>);
    /// without one, results that cover every kind of outcome.
    /// </summary>
    public const string DemoSwitch = "--demo";

    /// <summary>Followed by a file: save a picture of the window there, then exit.</summary>
    public const string ScreenshotSwitch = "--screenshot";

    public static AppRole Parse(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);

        bool smokeTest = false;
        bool demo = false;
        Scanning.DemoState state = Scanning.DemoState.Mixed;
        string? screenshot = null;

        for (int index = 0; index < args.Count; index++)
        {
            switch (args[index])
            {
                case SmokeTestSwitch when !smokeTest:
                    smokeTest = true;
                    break;

                case DemoSwitch when !demo:
                    demo = true;
                    if (index + 1 < args.Count && Scanning.DemoScan.StateNames.TryGetValue(args[index + 1], out state))
                    {
                        index++;
                    }

                    break;

                case ScreenshotSwitch when screenshot is null && index + 1 < args.Count && IsFileArgument(args[index + 1]):
                    screenshot = args[++index];
                    break;

                default:
                    return new InvalidRole();
            }
        }

        return new UiRole(smokeTest, demo, screenshot, state);
    }

    private static bool IsFileArgument(string text) =>
        !string.IsNullOrWhiteSpace(text) && !text.StartsWith("--", StringComparison.Ordinal);
}
