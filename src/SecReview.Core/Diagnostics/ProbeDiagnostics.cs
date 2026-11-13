using System.Globalization;
using SecReview.Probing;

namespace SecReview.Diagnostics;

/// <summary>
/// Runs every probe once and writes one line each: which reads work on this PC, which need
/// administrator rights, and which fail. For support, and for CI on real Windows.
/// </summary>
public static class ProbeDiagnostics
{
    private const string WindowsVersionKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

    /// <summary>A service present on every Windows edition, to prove the service reading works.</summary>
    private const string SampleService = "EventLog";

    /// <summary>The "Logon" audit subcategory, to prove the audit policy reading works.</summary>
    private static readonly Guid LogonAuditSubcategory = new("0cce9215-69ae-11d9-bed3-505054503030");

    /// <summary>The "Debug programs" user right, to prove the user rights reading works.</summary>
    private const string DebugProgramsRight = "SeDebugPrivilege";

    /// <summary>Writes the report. Returns false if any probe failed outright.</summary>
    public static bool Run(SystemProbes probes, TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(probes);
        ArgumentNullException.ThrowIfNull(output);

        bool allFine = true;

        allFine &= Report(
            output,
            "registry",
            probes.Registry.GetValue(RegistryRoot.LocalMachine, WindowsVersionKey, "CurrentBuild"),
            value => $"Windows build {value.Text}");
        allFine &= Report(output, "services", probes.Services.GetService(SampleService), Describe);
        allFine &= Report(output, "power plan", probes.Power.GetSettings(), Describe);
        allFine &= Report(output, "firewall", probes.Firewall.GetState(), Describe);
        allFine &= Report(
            output, "antivirus products", probes.SecurityCenter.GetProducts(SecurityProductKind.Antivirus), Describe);
        allFine &= Report(
            output, "firewall products", probes.SecurityCenter.GetProducts(SecurityProductKind.Firewall), Describe);
        allFine &= Report(output, "account policy", probes.AccountPolicy.GetPolicy(), Describe);
        allFine &= Report(output, "drive encryption", probes.DriveEncryption.GetFixedDrives(), Describe);
        allFine &= Report(output, "windows update", probes.WindowsUpdate.GetStatus(), Describe);
        allFine &= Report(
            output,
            "wmi",
            probes.Wmi.Query(@"ROOT\CIMV2", "Win32_OperatingSystem", ["Caption", "BuildNumber"]),
            systems => systems.Count == 0
                ? "no operating system object"
                : $"{systems[0].Text("Caption")}, build {systems[0].Text("BuildNumber")}");
        allFine &= Report(output, "firmware", probes.Platform.GetFirmware(), kind => kind.ToString());
        allFine &= Report(output, "tpm", probes.Platform.GetTpm(), version => version switch
        {
            TpmVersion.Version20 => "TPM 2.0",
            TpmVersion.Version12 => "TPM 1.2",
            _ => "none",
        });
        allFine &= Report(
            output,
            "code integrity",
            probes.Platform.GetCodeIntegrity(),
            state => $"test signing: {OnOff(state.TestSigning)}, kernel debugging: {OnOff(state.KernelDebugging)}, " +
                $"memory integrity: {OnOff(state.MemoryIntegrity)}");
        allFine &= Report(
            output,
            "uptime",
            probes.Environment.Uptime(),
            uptime => string.Create(CultureInfo.InvariantCulture, $"{uptime.TotalDays:F1} days"));
        allFine &= Report(
            output,
            "files",
            probes.Environment.Folder(KnownFolder.Windows) is { IsOk: true } windows
                ? probes.Files.List(windows.Value!)
                : ProbeFailure.Failed("Windows did not say where its folder is."),
            entries => $"Windows folder: {entries.Count} entries");
        allFine &= Report(
            output,
            "permissions",
            probes.Environment.Folder(KnownFolder.Windows) is { IsOk: true } folder
                ? probes.Access.ReadPath(folder.Value!)
                : ProbeFailure.Failed("Windows did not say where its folder is."),
            reading => $"Windows folder: {Describe(reading)}");
        allFine &= Report(
            output,
            "key permissions",
            probes.Access.ReadKey(RegistryRoot.LocalMachine, WindowsVersionKey),
            reading => $"Windows version key: {Describe(reading)}");

        // These two need administrator rights: "needs administrator" is the expected answer
        // for a normal user.
        allFine &= Report(
            output,
            "audit policy",
            probes.AuditPolicy.GetSubcategories([LogonAuditSubcategory]),
            settings => settings.TryGetValue(LogonAuditSubcategory, out AuditSetting logon)
                ? $"Logon: {logon}"
                : "Logon: not returned");
        allFine &= Report(
            output,
            "user rights",
            probes.UserRights.GetAccountsWithRight(DebugProgramsRight),
            accounts => $"{DebugProgramsRight}: " +
                (accounts.Count == 0 ? "nobody" : string.Join(", ", accounts.Select(a => a.Name ?? a.Sid))));

        return allFine;
    }

    private static bool Report<T>(TextWriter output, string name, ProbeResult<T> result, Func<T, string> describe)
    {
        string status = result.Status switch
        {
            ProbeStatus.Ok => "ok",
            ProbeStatus.NotFound => "not found",
            ProbeStatus.AccessDenied => "needs administrator",
            ProbeStatus.NotSupported => "not supported",
            _ => "FAILED",
        };

        string text = result.IsOk ? describe(result.Value!) : result.Detail ?? string.Empty;
        output.WriteLine($"{name,-20} {status,-20} {text}".TrimEnd());

        return result.Status != ProbeStatus.Failed;
    }

    private static string Describe(SecurityReading reading) => reading.HasList
        ? string.Create(CultureInfo.InvariantCulture, $"{reading.Entries.Count} entries, owner {reading.Owner}")
        : "no permission list";

    private static string Describe(IReadOnlyList<DriveEncryption> drives) => drives.Count == 0
        ? "no fixed drives"
        : string.Join("; ", drives.Select(drive => string.Create(
            CultureInfo.InvariantCulture,
            $"{drive.Drive}{(drive.IsSystemDrive ? " (system)" : string.Empty)} {drive.State}" +
            $"{(drive.RawValue is int raw ? $" [{raw}]" : string.Empty)}" +
            $"{(drive.Detail is null ? string.Empty : $" ({drive.Detail})")}")));

    private static string Describe(WindowsUpdateStatus status) =>
        $"updates: {status.Mode}, service {(status.ServiceAvailable ? "available" : "unavailable")}, " +
        $"restart {(status.RebootRequired ? "pending" : "not pending")}, " +
        $"last search {Date(status.LastSuccessfulSearch)}, last install {Date(status.LastSuccessfulInstall)}";

    private static string Date(DateTimeOffset? value) =>
        value is null ? "never" : value.Value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

    private static string OnOff(bool value) => value ? "on" : "off";

    private static string Describe(ServiceInfo service) =>
        $"{service.Name}: {service.StartType}, {(service.IsRunning ? "running" : "stopped")}";

    private static string Describe(PowerSettings settings) =>
        $"plugged in: {Describe(settings.PluggedIn)}; on battery: {Describe(settings.OnBattery)}; " +
        $"battery: {(settings.HasBattery ? "yes" : "no")}; modern standby: {(settings.ModernStandby ? "yes" : "no")}";

    private static string Describe(PowerSourceSettings source) =>
        $"display off {Minutes(source.DisplayOff, "never")}, sleep {Minutes(source.Sleep, "never")}, " +
        $"{(source.RequirePasswordOnWake ? "password on wake" : "no password on wake")}";

    private static string Describe(FirewallState state)
    {
        IEnumerable<string> profiles = state.Profiles.Select(profile =>
            $"{profile.Profile}: {(profile.Enabled ? "on" : "off")}" +
            $"{(profile.BlocksInboundByDefault ? ", blocks inbound" : ", allows inbound")}");
        return $"{string.Join("; ", profiles)}; active: {state.ActiveProfiles}";
    }

    private static string Describe(IReadOnlyList<SecurityProduct> products) => products.Count == 0
        ? "none registered"
        : string.Join("; ", products.Select(Describe));

    private static string Describe(SecurityProduct product)
    {
        string origin = product.IsBuiltIn ? "part of Windows" : "another vendor";
        return product.SignaturesUpToDate switch
        {
            null => $"{product.Name} ({product.State}, {origin})",
            true => $"{product.Name} ({product.State}, definitions current, {origin})",
            false => $"{product.Name} ({product.State}, definitions out of date, {origin})",
        };
    }

    private static string Describe(AccountPolicy policy)
    {
        // A threshold of 0 means accounts are never locked out; the duration then means nothing.
        string lockout = policy.LockoutThreshold == 0
            ? "no lockout"
            : string.Create(
                CultureInfo.InvariantCulture,
                $"lockout after {policy.LockoutThreshold} failed sign-ins for {Minutes(policy.LockoutDuration, "ever")}");

        return string.Create(
            CultureInfo.InvariantCulture,
            $"minimum length {policy.MinimumPasswordLength}, history {policy.PasswordHistoryLength}, " +
            $"maximum age {Days(policy.MaximumPasswordAge)}, {lockout}");
    }

    private static string Days(TimeSpan? value) =>
        value is null ? "never" : string.Create(CultureInfo.InvariantCulture, $"{value.Value.TotalDays:0} days");

    private static string Minutes(TimeSpan? value, string whenNull) =>
        value is null ? whenNull : string.Create(CultureInfo.InvariantCulture, $"{value.Value.TotalMinutes:0} min");
}
