namespace SecReview.Probing;

/// <summary>
/// What Windows Explorer knows about BitLocker on a drive, readable without administrator
/// rights.
/// </summary>
public enum DriveEncryptionState
{
    /// <summary>BitLocker protection is on.</summary>
    On,

    /// <summary>BitLocker is off.</summary>
    Off,

    /// <summary>
    /// Any other state (for example encrypting, suspended or locked). Microsoft does not document
    /// the individual values, so they are not interpreted here: the administrator check reads the
    /// documented details instead.
    /// </summary>
    Other,

    /// <summary>Windows reports nothing for this drive (for example an unsupported file system).</summary>
    NotReported,
}

/// <summary>BitLocker state of one fixed drive.</summary>
/// <param name="Drive">The drive, for example "C:".</param>
/// <param name="IsSystemDrive">Whether Windows is installed on it.</param>
/// <param name="State">The interpreted state.</param>
/// <param name="RawValue">The value Windows reported, for diagnostics; null if none.</param>
public sealed record DriveEncryption(string Drive, bool IsSystemDrive, DriveEncryptionState State, int? RawValue)
{
    /// <summary>
    /// Interprets the shell's <c>System.Volume.BitLockerProtection</c> value. Only 1 (on) and
    /// 2 (off) are taken as definite.
    /// </summary>
    public static DriveEncryptionState Interpret(int? rawValue) => rawValue switch
    {
        null => DriveEncryptionState.NotReported,
        1 => DriveEncryptionState.On,
        2 => DriveEncryptionState.Off,
        _ => DriveEncryptionState.Other,
    };
}

public interface IDriveEncryptionProbe
{
    /// <summary>Every fixed drive with its BitLocker state.</summary>
    ProbeResult<IReadOnlyList<DriveEncryption>> GetFixedDrives();
}
