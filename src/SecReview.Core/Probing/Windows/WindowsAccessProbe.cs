using System.Runtime.Versioning;
using System.Security.AccessControl;
using Microsoft.Win32;

namespace SecReview.Probing.Windows;

/// <summary>Reads permission lists from disk and the registry, read-only.</summary>
[SupportedOSPlatform(MinimumWindows.Platform)]
internal sealed class WindowsAccessProbe : IAccessProbe
{
    private const AccessControlSections Sections = AccessControlSections.Access | AccessControlSections.Owner;

    public ProbeResult<SecurityReading> ReadPath(string path)
    {
        if (!DiskFileProbe.IsFullPath(path))
        {
            return ProbeFailure.Failed("The location is not a path on this PC.");
        }

        try
        {
            FileAttributes attributes = File.GetAttributes(path);
            if (attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                return ProbeFailure.Failed(IAccessProbe.LinkDetail);
            }

            bool isFolder = attributes.HasFlag(FileAttributes.Directory);
            FileSystemSecurity security = isFolder ? new DirectorySecurity(path, Sections) : new FileSecurity(path, Sections);
            return Convert(isFolder ? SecuredKind.Folder : SecuredKind.File, security.GetSecurityDescriptorBinaryForm());
        }
#pragma warning disable CA1031 // A probe reports every failure as a result; none may escape.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            return WindowsError.FromException(exception, "Reading the permissions");
        }
    }

    public ProbeResult<SecurityReading> ReadKey(RegistryRoot root, string keyPath)
    {
        try
        {
            RegistryHive hive = root == RegistryRoot.CurrentUser ? RegistryHive.CurrentUser : RegistryHive.LocalMachine;
            using RegistryKey baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);

            // Asking only to read the permissions works on keys whose values may not be read.
            using RegistryKey? key = baseKey.OpenSubKey(keyPath, RegistryRights.ReadPermissions);
            return key is null
                ? ProbeFailure.NotFound()
                : Convert(SecuredKind.RegistryKey, key.GetAccessControl(Sections).GetSecurityDescriptorBinaryForm());
        }
#pragma warning disable CA1031 // A probe reports every failure as a result; none may escape.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            return WindowsError.FromException(exception, "Reading the key's permissions");
        }
    }

    public ProbeResult<DriveKind> Drive(char letter)
    {
        if (!char.IsAsciiLetter(letter))
        {
            return ProbeFailure.Failed("Not a drive letter.");
        }

        try
        {
            return ProbeResult<DriveKind>.Ok(new DriveInfo(letter.ToString()).DriveType switch
            {
                DriveType.Fixed => DriveKind.Fixed,
                DriveType.Removable => DriveKind.Removable,
                DriveType.Network => DriveKind.Network,
                DriveType.NoRootDirectory => DriveKind.Absent,
                DriveType.CDRom or DriveType.Ram => DriveKind.Other,
                _ => DriveKind.Unknown,
            });
        }
#pragma warning disable CA1031 // A probe reports every failure as a result; none may escape.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            return WindowsError.FromException(exception, "Reading the drive's kind");
        }
    }

    /// <summary>A stored security descriptor as plain data. Entries that neither allow nor deny (auditing) are left out.</summary>
    internal static ProbeResult<SecurityReading> Convert(SecuredKind kind, byte[] descriptor)
    {
        var raw = new RawSecurityDescriptor(descriptor, 0);
        var entries = new List<PermissionEntry>();
        if (raw.DiscretionaryAcl is { } list)
        {
            foreach (GenericAce ace in list)
            {
                if (ace is QualifiedAce { AceQualifier: AceQualifier.AccessAllowed or AceQualifier.AccessDenied } entry)
                {
                    entries.Add(new PermissionEntry(
                        entry.SecurityIdentifier.Value,
                        Allows: entry.AceQualifier == AceQualifier.AccessAllowed,
                        Rights: unchecked((uint)entry.AccessMask),
                        InheritOnly: entry.AceFlags.HasFlag(AceFlags.InheritOnly),
                        Conditional: entry.IsCallback));
                }
            }
        }

        return ProbeResult<SecurityReading>.Ok(
            new SecurityReading(kind, raw.Owner?.Value ?? string.Empty, HasList: raw.DiscretionaryAcl is not null, entries));
    }
}
