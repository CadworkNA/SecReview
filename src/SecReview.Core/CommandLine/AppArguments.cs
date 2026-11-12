namespace SecReview.CommandLine;

/// <summary>Parses SecReview.exe's arguments into the role the process takes.</summary>
public static class AppArguments
{
    /// <summary>Used by CI: load the window, render one frame, exit 0.</summary>
    public const string SmokeTestSwitch = "--smoke-test";

    public static AppRole Parse(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);

        bool smokeTest = false;
        foreach (string argument in args)
        {
            if (argument == SmokeTestSwitch && !smokeTest)
            {
                smokeTest = true;
            }
            else
            {
                return new InvalidRole("Unknown argument.");
            }
        }

        return new UiRole(smokeTest);
    }
}
