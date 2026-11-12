using System.Diagnostics;
using SecReview.Checks;
using SecReview.CommandLine;
using SecReview.Diagnostics;
using SecReview.Instances;
using SecReview.Probing;
using SecReview.Probing.Windows;
using SecReview.Scanning;
using SecReview.Settings;
using SecReview.Tray;
using SecReview.Tray.Windows;
using SecReview.Updates;

namespace SecReview.App;

/// <summary>
/// The process behind the notification-area icon. It touches no XAML type, so the UI framework
/// is never started and the process stays small. The rules are in <see cref="TraySession"/>;
/// this ties them to Windows: the icon, the scanner, the files and the window.
/// </summary>
internal static class TrayApp
{
    /// <summary>The smoke test has not finished by then: it has failed.</summary>
    private static readonly TimeSpan SmokeTestLimit = TimeSpan.FromSeconds(90);

    public static int Run(TrayRole role)
    {
        if (!WindowsProbes.IsSupported)
        {
            return ExitCode.UnsupportedWindows;
        }

        using Timer? watchdog = role.SmokeTest
            ? new Timer(_ => Environment.Exit(ExitCode.SmokeTestTimedOut), null, SmokeTestLimit, Timeout.InfiniteTimeSpan)
            : null;

        string data = AppData.Directory;
        AppLog log = AppLog.ForThisProcess();

        // The icon stays all day and opens the window. With administrator rights from the
        // Windows prompt it would hand those rights to whatever it starts, so it does not run.
        if (WindowsProbes.IsElevatedByPrompt())
        {
            log.Info("The notification-area icon was started as administrator and did not run. It starts at the next sign-in.");
            return ExitCode.Ok;
        }

        // One icon per user. A second start has nothing to add. An icon that is just leaving
        // (switched off and on again) still holds the claim for a moment.
        SingleInstance? claimed = null;
        for (int attempt = 0; attempt < 10 && (claimed = SingleInstance.TryClaim(InstanceNames.Tray(data))) is null; attempt++)
        {
            Thread.Sleep(200);
        }

        using SingleInstance? claim = claimed;
        if (claim is null)
        {
            log.Info("The notification-area icon did not start: there is one already.");
            return ExitCode.Ok;
        }

        // A build machine's errors are the build's business, as with the window's smoke test.
        using var reporter = new ErrorReporter(
            role.SmokeTest ? null : ErrorReporter.CompiledAddress,
            log,
            PrivacyFilter.ForThisProcess(),
            new ErrorReportBudget(data, TimeProvider.System));

        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
        {
            if (e.ExceptionObject is Exception exception)
            {
                log.Error("Unhandled error behind the notification-area icon", exception);
                reporter.Report(exception);
                reporter.Flush();
            }
        };

        try
        {
            return Run(role, data, log, reporter);
        }
#pragma warning disable CA1031 // Last resort: record why the icon could not run, then fail visibly.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            log.Error("The notification-area icon could not run", exception);
            reporter.Report(exception);
            return ExitCode.UnhandledError;
        }
    }

    private static int Run(TrayRole role, string data, AppLog log, ErrorReporter reporter)
    {
        // The checks must not slow down what the user is doing. This lowers only this process.
        try
        {
            using var self = Process.GetCurrentProcess();
            self.PriorityClass = ProcessPriorityClass.BelowNormal;
        }
        catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            // It then runs at the ordinary priority.
        }

        IRegistryProbe registry = WindowsProbes.Create().Registry;
        TraySession? session = null;

        // Once a day the icon also looks for a newer SecReview. What it finds is kept for the
        // window, and the check "SecReview is up to date" reads it at the next scan.
        UpdateService updates = UpdateService.ForThisBuild(data, registry);
        using var icon = new NotificationAreaIcon(command =>
        {
            session?.Handle(command);
            if (command == TrayCommand.Tick && !role.SmokeTest)
            {
                _ = updates.LookAsync();
            }
        });

        session = new TraySession(icon, new TrayEnvironment
        {
            Settings = new SettingsStore(data),
            Results = new ResultsStore(data),
            Clock = TimeProvider.System,
            Scan = () => new Scanner(WindowsProbes.Create(), TimeProvider.System)
            {
                // A check that throws is a bug in SecReview: its type and place are reported, never its message.
                OnUnexpectedError = (checkId, error) => reporter.Report(error, checkId),
            }.RunAsync(CheckSelection.All, WindowsProbes.IsProcessElevated()),
            OpenWindow = checkId => OpenWindow(checkId, log),
            OnError = (where, exception) =>
            {
                log.Error(where, exception);
                if (exception is not IOException)
                {
                    reporter.Report(exception);
                }
            },
            DarkTaskbar = () => IsTaskbarDark(registry),

            // Reports follow the same switch, policy and first-run notice as in the window.
            OnSettings = (settings, wereRead) =>
                reporter.Apply(new ErrorReportsChoice(settings.SendErrorReports, wereRead, settings.FirstRunDone), registry),
        });

        if (!session.Start())
        {
            return ExitCode.Ok; // switched off in Settings
        }

        // The window says when it changed the settings or the results, so the icon follows at once.
        // However often it is signalled, one look is waiting at most.
        int waiting = 0;
        using WakeSignal? wake = WakeSignal.Listen(InstanceNames.TrayWake(data), () =>
        {
            if (Interlocked.Exchange(ref waiting, 1) == 0)
            {
                icon.Post(() =>
                {
                    Volatile.Write(ref waiting, 0);
                    session.Handle(TrayCommand.Tick);
                });
            }
        });
        icon.StartTimer(TraySession.TickInterval);

        if (role.SmokeTest)
        {
            // One scan, then out. Whether Windows took the icon is said, not required: a build
            // machine may have no notification area.
            log.Info(icon.IsShown ? "Smoke test: the icon is shown." : "Smoke test: Windows has no notification area here.");
            session.Handle(TrayCommand.CheckNow);
            session.Idle.ContinueWith(_ => icon.Quit(), TaskScheduler.Default);
        }

        icon.Run();

        return role.SmokeTest && session.Last is null ? ExitCode.ScanFailed : ExitCode.Ok;
    }

    /// <summary>Starts the window, or brings the open one forward; both are the window's own start.</summary>
    private static void OpenWindow(string? checkId, AppLog log)
    {
        if (Environment.ProcessPath is not { } self)
        {
            return;
        }

        try
        {
            var start = new ProcessStartInfo(self) { UseShellExecute = false };
            if (ErrorReports.IsCheckId(checkId))
            {
                start.ArgumentList.Add(AppArguments.ShowSwitch);
                start.ArgumentList.Add(checkId);
            }

            using Process? started = Process.Start(start);
        }
        catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            log.Error("The window could not be opened from the notification-area icon", exception);
        }
    }

    /// <summary>Whether Windows' own colours (taskbar, Start) are dark. Dark when it cannot be told: Windows' default.</summary>
    private static bool IsTaskbarDark(IRegistryProbe registry)
    {
        ProbeResult<RegistryValue> light = registry.GetValue(
            RegistryRoot.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", "SystemUsesLightTheme");
        return !(light.Status == ProbeStatus.Ok && light.Value is { Type: RegistryValueType.Number, Number: not 0 });
    }
}
