using SecReview.Probing;

namespace SecReview.Checks.BuiltIn;

/// <summary>
/// BitLocker must be on for the Windows drive and every other fixed drive.
/// <para>
/// As a normal user only "on" and "off" can be told apart for certain (Windows documents no
/// more than that for what it shows a normal user), so any other state is reported as needing
/// the administrator check. With administrator rights the documented BitLocker management
/// class answers precisely: on, off, suspended, still encrypting or decrypting.
/// </para>
/// </summary>
public sealed class DriveEncryptionCheck : ICheck
{
    public const string Id = "disk.encryption";

    internal const string WmiNamespace = @"ROOT\CIMV2\Security\MicrosoftVolumeEncryption";
    internal const string WmiClass = "Win32_EncryptableVolume";

    private const string Expected = "On";

    private static readonly string[] WmiProperties = ["DriveLetter", "ProtectionStatus", "ConversionStatus"];

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SystemIntegrity, Severity.High, AdminNeed.ForFullDetail);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        ProbeResult<IReadOnlyList<DriveEncryption>> result = context.Probes.DriveEncryption.GetFixedDrives();
        if (!result.IsOk)
        {
            return ProbeOutcomes.FromFailure(result, "the BitLocker state of the drives");
        }

        IReadOnlyList<DriveEncryption> drives = result.Value!;
        if (!drives.Any(d => d.IsSystemDrive))
        {
            return CheckOutcome.Error("Windows did not report the drive it is installed on.");
        }

        string? detailsFailure = null;
        Dictionary<string, WmiObject> details = context.IsElevated
            ? ReadDetails(context.Probes.Wmi, out detailsFailure)
            : [];

        var states = new List<(DriveEncryption Drive, Verdict Verdict, string Found)>(drives.Count);
        foreach (DriveEncryption drive in drives)
        {
            (Verdict verdict, string found) = details.TryGetValue(drive.Drive, out WmiObject? detail)
                ? FromDetail(detail)
                : FromShell(drive);
            states.Add((drive, verdict, found));
        }

        List<Finding> findings = [.. states.Select(s =>
        {
            string item = s.Drive.IsSystemDrive ? $"{s.Drive.Drive} (Windows)" : s.Drive.Drive;
            return s.Verdict == Verdict.Protected
                ? Finding.Ok(item, s.Found, Expected)
                : Finding.Problem(item, s.Found, Expected);
        })];

        List<string> unprotected = [.. states.Where(s => s.Verdict == Verdict.NotProtected).Select(s => s.Drive.Drive)];
        if (unprotected.Count > 0)
        {
            // Name the precise state when every unprotected drive is in the same one.
            string[] kinds = [.. states.Where(s => s.Verdict == Verdict.NotProtected).Select(s => s.Found).Distinct()];
            string what = kinds.Length == 1 ? kinds[0].ToLowerInvariant() : "not protecting";
            return CheckOutcome.Fail(
                kinds.Length == 1
                    ? $"BitLocker is {what} on {Wording.JoinWithAnd(unprotected)}."
                    : $"BitLocker is not protecting {Wording.JoinWithAnd(unprotected)}.",
                findings);
        }

        List<string> unknown = [.. states.Where(s => s.Verdict == Verdict.Unknown).Select(s => s.Drive.Drive)];
        if (unknown.Count > 0)
        {
            string which = $"{Wording.JoinWithAnd(unknown)} {Wording.IsOrAre(unknown.Count)}";
            if (!context.IsElevated)
            {
                return CheckOutcome.NeedsAdmin(
                    $"Windows does not confirm that {which} fully protected. The administrator check reads the details.",
                    findings);
            }

            // Say which of the two things went wrong: the details could not be read at all, or
            // they were read and BitLocker itself does not know (a locked drive).
            return detailsFailure is not null
                ? CheckOutcome.Error(
                    $"The BitLocker details could not be read, so it is not known whether {which} protected. {detailsFailure}",
                    findings)
                : CheckOutcome.Error(
                    $"Windows cannot say whether {which} protected; a drive may be locked.", findings);
        }

        return CheckOutcome.Pass(
            drives.Count == 1 ? $"BitLocker is on for {drives[0].Drive}." : $"BitLocker is on for all {drives.Count} drives.",
            findings);
    }

    /// <summary>What a normal user can see: on, off, or something that needs a closer look.</summary>
    private static (Verdict Verdict, string Found) FromShell(DriveEncryption drive) => drive.State switch
    {
        DriveEncryptionState.On => (Verdict.Protected, "On"),
        DriveEncryptionState.Off => (Verdict.NotProtected, "Off"),
        DriveEncryptionState.Other => (Verdict.Unknown, "Not fully protected"),
        DriveEncryptionState.NotReported => (Verdict.Unknown, "Not reported by Windows"),
        _ => (Verdict.Unknown, drive.Detail ?? "Could not be read"),
    };

    /// <summary>
    /// The documented meaning of Win32_EncryptableVolume's ProtectionStatus (0 off, 1 on,
    /// 2 unknown) and ConversionStatus (0 decrypted, 1 encrypted, 2 encrypting, 3 decrypting,
    /// 4 encryption paused, 5 decryption paused). Protection "off" on a fully encrypted drive
    /// means BitLocker is suspended: the key is stored unprotected on the disk.
    /// </summary>
    private static (Verdict Verdict, string Found) FromDetail(WmiObject detail)
    {
        long? protection = detail.Number("ProtectionStatus");
        long? conversion = detail.Number("ConversionStatus");

        return protection switch
        {
            1 => (Verdict.Protected, "On"),
            0 => (Verdict.NotProtected, conversion switch
            {
                0 => "Off",
                1 => "Suspended",
                2 => "Still encrypting",
                3 => "Being decrypted",
                4 => "Paused while encrypting",
                5 => "Paused while decrypting",
                _ => "Off",
            }),
            _ => (Verdict.Unknown, "Locked or not determined"),
        };
    }

    /// <summary>
    /// Drive letter ("C:") to its BitLocker details. Empty, with the reason in
    /// <paramref name="failure"/>, if they cannot be read.
    /// </summary>
    private static Dictionary<string, WmiObject> ReadDetails(IWmiProbe wmi, out string? failure)
    {
        failure = null;
        var details = new Dictionary<string, WmiObject>(StringComparer.OrdinalIgnoreCase);
        ProbeResult<IReadOnlyList<WmiObject>> volumes = wmi.Query(WmiNamespace, WmiClass, WmiProperties);
        if (!volumes.IsOk)
        {
            // Falls back to what a normal user sees; an unconfirmed drive then becomes
            // "could not check", with this reason, rather than a guess.
            failure = volumes.Detail ?? $"Reading them ended with: {volumes.Status}.";
            return details;
        }

        foreach (WmiObject volume in volumes.Value!)
        {
            if (volume.Text("DriveLetter") is { Length: > 0 } letter)
            {
                details[letter] = volume;
            }
        }

        return details;
    }

    private enum Verdict
    {
        Unknown = 0,
        Protected,
        NotProtected,
    }
}
