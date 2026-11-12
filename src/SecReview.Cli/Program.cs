using SecReview;
using SecReview.Checks;
using SecReview.CommandLine;
using SecReview.Diagnostics;
using SecReview.Elevation;
using SecReview.Probing;
using SecReview.Probing.Windows;
using SecReview.Reporting;
using SecReview.Scanning;
using SecReview.Updates;
using SecReview.Updates.Windows;

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

    case ElevatedScanCommand elevated:
        if (!WindowsProbes.IsSupported)
        {
            return UnsupportedWindows();
        }

        // Nothing is printed: this runs hidden, started by the app, and answers on the pipe only.
        return await ElevatedHelper.RunAsync(
            elevated.PipeName, WindowsProbes.Create(), WindowsProbes.IsProcessElevated(), TimeProvider.System, CheckCatalogue.Checks, CheckCatalogue.Texts)
            ? ExitCode.Ok
            : ExitCode.ElevatedScanFailed;

    case ApplyUpdateCommand update:
        if (!WindowsProbes.IsSupported)
        {
            return UnsupportedWindows();
        }

        // Nothing is printed, as above. Everything it works with is compiled in or read from
        // the PC by this process: the update address, the publisher, the organisation's policy.
        using (var downloader = new HttpUpdateTransport(UpdateSource.Compiled, timeout: TimeSpan.FromMinutes(10)))
        {
            return await UpdateApplier.RunAsync(
                update.PipeName,
                UpdateSource.Compiled,
                PublisherIdentity.Compiled,
                UpdatePolicy.Read(WindowsProbes.Create().Registry),
                ProductInfo.Version,
                downloader,
                new WindowsUpdateHost(),
                TimeProvider.System)
                ? ExitCode.Ok
                : ExitCode.UpdateNotInstalled;
        }

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
        ReportFile.Write(report, path, replaceExisting: !isElevated);
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
