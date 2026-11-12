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

    /// <summary>Followed by a file: write there what error reports would hold, send nothing, exit.</summary>
    public const string ErrorReportTestSwitch = "--error-report-test";

    /// <summary>Be the notification-area icon instead of the window. May be followed by <see cref="SmokeTestSwitch"/>.</summary>
    public const string TraySwitch = "--tray";

    /// <summary>Followed by a check's identifier: open the window on that check.</summary>
    public const string ShowSwitch = "--show";

    public static AppRole Parse(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);

        if (args is [TraySwitch])
        {
            return new TrayRole();
        }

        if (args is [TraySwitch, SmokeTestSwitch])
        {
            return new TrayRole(SmokeTest: true);
        }

        if (args is [ErrorReportTestSwitch, var output] && IsFileArgument(output))
        {
            return new ErrorReportTestRole(output);
        }

        bool smokeTest = false;
        bool demo = false;
        Scanning.DemoState state = Scanning.DemoState.Mixed;
        string? screenshot = null;
        string? show = null;

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

                // An identifier never starts with a dash, so a switch is not taken for one.
                case ShowSwitch when show is null && index + 1 < args.Count && args[index + 1] is not ['-', ..] && Diagnostics.ErrorReports.IsCheckId(args[index + 1]):
                    show = args[++index];
                    break;

                default:
                    return new InvalidRole();
            }
        }

        return new UiRole(smokeTest, demo, screenshot, state, show);
    }

    private static bool IsFileArgument(string text) =>
        !string.IsNullOrWhiteSpace(text) && !text.StartsWith("--", StringComparison.Ordinal);
}
