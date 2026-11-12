using SecReview;
using SecReview.Checks;
using SecReview.CommandLine;
using SecReview.Diagnostics;
using SecReview.Probing;
using SecReview.Probing.Windows;
using SecReview.Reporting;
using SecReview.Scanning;

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
            return UnsupportedWindows();
        }

        return ProbeDiagnostics.Run(WindowsProbes.Create(), Console.Out) ? ExitCode.Ok : ExitCode.ProbeFailed;

    case ReportCommand report:
        if (!WindowsProbes.IsSupported)
        {
            return UnsupportedWindows();
        }

        return await WriteReportAsync(WindowsProbes.Create(), WindowsProbes.IsProcessElevated(), report.Path);

    case InvalidCommand invalid:
        Console.Error.WriteLine(invalid.Message);
        Console.Error.WriteLine(CliArguments.Usage);
        return ExitCode.Usage;

    default:
        throw new InvalidOperationException("Unhandled command.");
}

static int UnsupportedWindows()
{
    Console.Error.WriteLine($"SecReview needs {WindowsProbes.MinimumWindowsName} or later.");
    return ExitCode.UnsupportedWindows;
}

// Runs every check with whatever rights this process has and writes the results. Started from
// an elevated prompt, the administrator-only checks are answered too. The exit code says
// whether the report was written, not whether the PC passed: the report holds the results.
static async Task<int> WriteReportAsync(SystemProbes probes, bool isElevated, string path)
{
    ScanResult scan = await new Scanner(probes, TimeProvider.System).RunAsync(CheckSelection.All, isElevated);
    ScanReport report = ReportBuilder.Build(scan);

    try
    {
        ReportFile.Write(report, path);
    }
    catch (Exception exception) when (exception is IOException or UnauthorizedAccessException
        or ArgumentException or NotSupportedException)
    {
        Console.Error.WriteLine($"The report could not be written: {exception.Message}");
        return ExitCode.ReportNotWritten;
    }

    ReportCounts counts = report.Counts;
    Console.Out.WriteLine(
        $"{report.Checks.Count} checks: {counts.Pass} pass, {counts.Fail} fail, " +
        $"{counts.NeedsAdmin} need administrator rights, {counts.NotApplicable} not applicable, " +
        $"{counts.Error} could not be checked.");
    return ExitCode.Ok;
}
