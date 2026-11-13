namespace SecReview.Probing;

/// <summary>What a list of permissions belongs to. The same bits mean different things for each.</summary>
public enum SecuredKind
{
    File,
    Folder,
    RegistryKey,
}

/// <summary>One entry of a permission list, as stored. Nothing is judged here.</summary>
/// <param name="Sid">Who the entry is for, as a security identifier ("S-1-5-32-545").</param>
/// <param name="Allows">True for an entry that allows, false for one that denies.</param>
/// <param name="Rights">The access mask, generic bits included.</param>
/// <param name="InheritOnly">True when the entry is only handed down and does not apply here.</param>
/// <param name="Conditional">True when the entry applies only under a condition Windows evaluates.</param>
public sealed record PermissionEntry(string Sid, bool Allows, uint Rights, bool InheritOnly = false, bool Conditional = false);

/// <summary>Who owns a file, folder or registry key and who may do what with it.</summary>
/// <param name="Kind">What was read.</param>
/// <param name="Owner">The owner's security identifier; empty when Windows gave none.</param>
/// <param name="HasList">
/// False when there is no permission list at all, which lets everyone do everything. An empty
/// list is the opposite: nobody but the owner gets in.
/// </param>
/// <param name="Entries">The entries, in the order Windows applies them.</param>
public sealed record SecurityReading(SecuredKind Kind, string Owner, bool HasList, IReadOnlyList<PermissionEntry> Entries);

/// <summary>What a drive letter stands for.</summary>
public enum DriveKind
{
    /// <summary>Windows did not say.</summary>
    Unknown = 0,

    /// <summary>A disk in this PC.</summary>
    Fixed,

    /// <summary>A disk that can be taken out, such as a USB stick.</summary>
    Removable,

    /// <summary>A folder on another computer.</summary>
    Network,

    /// <summary>Anything else: an optical drive, a memory disk.</summary>
    Other,

    /// <summary>No drive has this letter.</summary>
    Absent,
}

/// <summary>
/// Reads who may change a file, a folder or a registry key. Only the stored list is read:
/// nothing is opened for writing, and no attempt is made to write.
/// </summary>
public interface IAccessProbe
{
    /// <summary>
    /// The <see cref="ProbeResult{T}.Detail"/> of a read refused because the path is a link or
    /// junction. Links are not followed: the permissions that count are those of the place a
    /// link stands in, and its target may be anywhere.
    /// </summary>
    const string LinkDetail = "The path is a link and was not followed.";

    /// <summary>
    /// The permissions of a file or folder on a drive of this PC ("C:\..."). Network and
    /// device paths are refused, as they are for reading files.
    /// </summary>
    ProbeResult<SecurityReading> ReadPath(string path);

    /// <summary>The permissions of a registry key.</summary>
    ProbeResult<SecurityReading> ReadKey(RegistryRoot root, string keyPath);

    /// <summary>What a drive letter stands for. Nothing on the drive is opened.</summary>
    ProbeResult<DriveKind> Drive(char letter);
}
