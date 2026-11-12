using System.Globalization;
using SecReview.Catalogue;
using SecReview.Probing;

namespace SecReview.Checks.BuiltIn;

/// <summary>
/// Windows must download updates by itself, and security updates must not be paused. A pause
/// of feature updates only is listed, not failed: security updates still arrive.
/// </summary>
public sealed class AutomaticUpdatesCheck : ICheck
{
    public const string Id = "updates.automatic";

    /// <summary>Where Windows records whether updates are paused (1 = paused).</summary>
    internal const string PauseStatusKey = @"SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\Settings";
    internal const string QualityPaused = "PausedQualityStatus";
    internal const string FeaturePaused = "PausedFeatureStatus";

    /// <summary>Where the Settings app keeps the end of a "Pause updates" period.</summary>
    internal const string SettingsKey = @"SOFTWARE\Microsoft\WindowsUpdate\UX\Settings";
    internal const string PauseExpiry = "PauseUpdatesExpiryTime";

    private const string What = "whether updates are paused";
    private const string Automatic = "Automatic updates";
    private const string Paused = "Security updates paused";

    public CheckDefinition Definition { get; } = new(Id, CheckCategory.Updates, Severity.High);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        ProbeResult<WindowsUpdateStatus> read = context.Probes.WindowsUpdate.GetStatus();
        if (!read.IsOk)
        {
            return ProbeOutcomes.FromFailure(read, "the Windows Update settings");
        }

        IRegistryProbe registry = context.Probes.Registry;
        if (RegistryReader.Number(registry, RegistryRoot.LocalMachine, PauseStatusKey, QualityPaused, What, out long? quality) is { } f1)
        {
            return f1;
        }

        if (RegistryReader.Number(registry, RegistryRoot.LocalMachine, PauseStatusKey, FeaturePaused, What, out long? feature) is { } f2)
        {
            return f2;
        }

        if (RegistryReader.Text(registry, RegistryRoot.LocalMachine, SettingsKey, PauseExpiry, What, out string? expiryText) is { } f3)
        {
            return f3;
        }

        WindowsUpdateStatus status = read.Value!;
        DateTimeOffset now = context.Clock.GetUtcNow();
        DateTimeOffset? pausedUntil = DateTimeOffset.TryParse(
            expiryText, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out DateTimeOffset expiry) && expiry > now
            ? expiry
            : null;
        bool paused = quality == 1 || pausedUntil is not null;

        (bool automatic, string mode) = status.Mode switch
        {
            AutomaticUpdateMode.Disabled => (false, "Off"),
            AutomaticUpdateMode.NotifyBeforeDownload => (false, "Only tells you about updates"),
            AutomaticUpdateMode.NotifyBeforeInstall => (true, "Downloads, then asks before installing"),
            _ => (true, "On"),
        };
        if (!status.ServiceAvailable)
        {
            (automatic, mode) = (false, "The update service is not available");
        }

        var findings = new List<Finding>
        {
            automatic ? Finding.Ok(Automatic, mode, "On") : Finding.Problem(Automatic, mode, "On"),
            paused
                ? Finding.Problem(
                    Paused,
                    pausedUntil is { } until ? $"Yes, until {Wording.Date(DateOnly.FromDateTime(until.UtcDateTime))}" : "Yes",
                    "No",
                    pausedUntil is not null ? $@"HKLM\{SettingsKey}\{PauseExpiry}" : $@"HKLM\{PauseStatusKey}\{QualityPaused}")
                : Finding.Ok(Paused, "No", "No"),
        };
        if (!paused && feature == 1)
        {
            findings.Add(Finding.Note("Feature updates paused", "Yes", $@"HKLM\{PauseStatusKey}\{FeaturePaused}"));
        }

        return (automatic, paused) switch
        {
            (false, true) => CheckOutcome.Fail("Automatic updates are off and updates are paused.", findings),
            (false, false) => CheckOutcome.Fail(
                status.ServiceAvailable ? "Windows does not install updates by itself." : "The Windows Update service is not available.",
                findings),
            (true, true) => CheckOutcome.Fail("Updates are paused.", findings),
            _ => CheckOutcome.Pass("Windows installs updates by itself.", findings),
        };
    }
}

/// <summary>
/// Windows must have installed an update recently. Monthly security updates plus a margin give
/// <see cref="MaximumAge"/>; a longer gap means updates are not arriving.
/// </summary>
public sealed class RecentUpdatesCheck : ICheck
{
    public const string Id = "updates.recent";

    public static readonly TimeSpan MaximumAge = TimeSpan.FromDays(35);

    private const string Item = "Last update installed";
    private const string Expected = "Within 35 days";

    public CheckDefinition Definition { get; } = new(Id, CheckCategory.Updates, Severity.High);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        ProbeResult<WindowsUpdateStatus> read = context.Probes.WindowsUpdate.GetStatus();
        if (!read.IsOk)
        {
            return ProbeOutcomes.FromFailure(read, "when updates were last installed");
        }

        if (read.Value!.LastSuccessfulInstall is not { } last)
        {
            return CheckOutcome.Error("Windows does not say when it last installed an update.");
        }

        TimeSpan age = context.Clock.GetUtcNow() - last;
        if (age < TimeSpan.Zero)
        {
            age = TimeSpan.Zero;
        }

        string found = age < TimeSpan.FromDays(1) ? "Today" : $"{(int)age.TotalDays} day{Wording.Plural((int)age.TotalDays)} ago";
        return age > MaximumAge
            ? CheckOutcome.Fail(
                $"Windows last installed an update {(int)age.TotalDays} days ago.", Finding.Problem(Item, found, Expected))
            : CheckOutcome.Pass(
                age < TimeSpan.FromDays(1) ? "Windows installed an update today." : $"Windows installed an update {found}.",
                Finding.Ok(Item, found, Expected));
    }
}

/// <summary>
/// The PC must be restarted now and then: many updates only take effect after a restart, and a
/// restart that an update is waiting for must not be put off.
/// </summary>
public sealed class RestartCheck : ICheck
{
    public const string Id = "updates.restart";

    public static readonly TimeSpan MaximumUptime = TimeSpan.FromDays(14);

    private const string Pending = "Restart needed for updates";
    private const string Running = "Running without a restart for";
    private const string ExpectedUptime = "14 days or less";

    public CheckDefinition Definition { get; } = new(Id, CheckCategory.Updates, Severity.Low);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        ProbeResult<TimeSpan> uptime = context.Probes.Environment.Uptime();
        if (!uptime.IsOk)
        {
            return ProbeOutcomes.FromFailure(uptime, "how long Windows has been running");
        }

        ProbeResult<WindowsUpdateStatus> updates = context.Probes.WindowsUpdate.GetStatus();
        if (!updates.IsOk)
        {
            return ProbeOutcomes.FromFailure(updates, "whether an update is waiting for a restart");
        }

        bool pending = updates.Value!.RebootRequired;
        bool tooLong = uptime.Value > MaximumUptime;
        string ran = Wording.Duration(uptime.Value);
        List<Finding> findings =
        [
            pending ? Finding.Problem(Pending, "Yes", "No") : Finding.Ok(Pending, "No", "No"),
            tooLong ? Finding.Problem(Running, ran, ExpectedUptime) : Finding.Ok(Running, ran, ExpectedUptime),
        ];

        if (pending)
        {
            return CheckOutcome.Fail("An update is waiting for a restart.", findings);
        }

        return tooLong
            ? CheckOutcome.Fail($"This PC has not been restarted for {ran}.", findings)
            : CheckOutcome.Pass($"This PC was restarted {ran} ago and no update is waiting.", findings);
    }
}

/// <summary>
/// The installed Windows release must still get security updates. The dates come from the
/// list shipped with the app (<see cref="WindowsServicing"/>); a release that is not on the
/// list is "could not check", never a pass.
/// </summary>
public sealed class WindowsSupportedCheck : ICheck
{
    public const string Id = "updates.supported";

    internal const string VersionKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    internal const string BuildValue = "CurrentBuildNumber";
    internal const string EditionValue = "EditionID";
    internal const string InstallationValue = "InstallationType";

    private const string What = "the Windows version";
    private const string Expected = "Still updated";

    private static readonly string[] EnterpriseEditions =
        ["Enterprise", "EnterpriseN", "EnterpriseG", "EnterpriseGN", "Education", "EducationN", "IoTEnterprise", "IoTEnterpriseK", "ServerRdsh"];

    private static readonly string[] LongTermEditions = ["EnterpriseS", "EnterpriseSN", "IoTEnterpriseS", "IoTEnterpriseSK"];

    private readonly WindowsServicing _servicing;

    public WindowsSupportedCheck()
        : this(WindowsServicing.Current)
    {
    }

    internal WindowsSupportedCheck(WindowsServicing servicing) => _servicing = servicing;

    public CheckDefinition Definition { get; } = new(Id, CheckCategory.Updates, Severity.High);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        IRegistryProbe registry = context.Probes.Registry;

        if (RegistryReader.Number(registry, RegistryRoot.LocalMachine, VersionKey, BuildValue, What, out long? build) is { } f1)
        {
            return f1;
        }

        if (RegistryReader.Text(registry, RegistryRoot.LocalMachine, VersionKey, EditionValue, What, out string? edition) is { } f2)
        {
            return f2;
        }

        if (RegistryReader.Text(registry, RegistryRoot.LocalMachine, VersionKey, InstallationValue, What, out string? installation) is { } f3)
        {
            return f3;
        }

        if (build is null)
        {
            return CheckOutcome.Error("Windows did not report its build number.");
        }

        if (installation?.StartsWith("Server", StringComparison.OrdinalIgnoreCase) == true)
        {
            return CheckOutcome.NotApplicable("Windows Server has its own update periods, which SecReview does not track.");
        }

        (string Name, DateOnly End)? release = Find((int)build.Value, edition);
        if (release is null)
        {
            int newest = _servicing.Releases.Max(r => r.Build);
            string listDate = Wording.Date(_servicing.Verified);
            return CheckOutcome.Error(build > newest
                ? $"Windows build {build} is newer than SecReview's list of {listDate}. Update SecReview."
                : $"Windows build {build} is not on SecReview's list of {listDate}; it may be a preview or a very old release.");
        }

        (string name, DateOnly end) = release.Value;
        DateOnly today = DateOnly.FromDateTime(context.Clock.GetUtcNow().UtcDateTime);
        return today > end
            ? CheckOutcome.Fail(
                $"{name} stopped getting security updates on {Wording.Date(end)}.",
                Finding.Problem(name, $"Updates ended {Wording.Date(end)}", Expected, _servicing.Source))
            : CheckOutcome.Pass(
                $"{name} gets security updates until {Wording.Date(end)}.",
                Finding.Ok(name, $"Updated until {Wording.Date(end)}", Expected, _servicing.Source));
    }

    private (string Name, DateOnly End)? Find(int build, string? edition)
    {
        if (edition is not null && LongTermEditions.Contains(edition, StringComparer.OrdinalIgnoreCase))
        {
            return _servicing.LongTerm.FirstOrDefault(r => r.Build == build) is { } longTerm
                ? (longTerm.Name, edition.StartsWith("IoT", StringComparison.OrdinalIgnoreCase) ? longTerm.Iot : longTerm.Enterprise)
                : null;
        }

        if (_servicing.Releases.FirstOrDefault(r => r.Build == build) is not { } release)
        {
            return null;
        }

        // An edition that is not recognised gets the earlier, Home and Pro, date.
        bool enterprise = edition is not null && EnterpriseEditions.Contains(edition, StringComparer.OrdinalIgnoreCase);
        return (release.Name, enterprise ? release.Enterprise : release.HomePro);
    }
}
