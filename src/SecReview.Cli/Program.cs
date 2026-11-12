using SecReview;
using SecReview.CommandLine;
using SecReview.Diagnostics;
using SecReview.Probing.Windows;

switch (CliArguments.Parse(args))
{
    case HelpCommand:
        Console.Out.WriteLine(CliArguments.Usage);
        return ExitCode.Ok;

    case VersionCommand:
        Console.Out.WriteLine($"{ProductInfo.Name} {ProductInfo.Version}");
        return ExitCode.Ok;

    case DiagnoseCommand:
        if (!WindowsProbes.IsSupported)
        {
            Console.Error.WriteLine($"SecReview needs {WindowsProbes.MinimumWindowsName} or later.");
            return ExitCode.UnsupportedWindows;
        }

        return ProbeDiagnostics.Run(WindowsProbes.Create(), Console.Out) ? ExitCode.Ok : ExitCode.ProbeFailed;

    case InvalidCommand invalid:
        Console.Error.WriteLine(invalid.Message);
        Console.Error.WriteLine(CliArguments.Usage);
        return ExitCode.Usage;

    default:
        throw new InvalidOperationException("Unhandled command.");
}
