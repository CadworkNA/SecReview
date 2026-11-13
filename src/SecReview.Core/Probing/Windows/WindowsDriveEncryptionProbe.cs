using System.Runtime.Versioning;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.System.Com.StructuredStorage;
using Windows.Win32.System.Variant;
using Windows.Win32.UI.Shell.PropertiesSystem;

namespace SecReview.Probing.Windows;

/// <summary>
/// Reads each fixed drive's BitLocker state from the shell property
/// <c>System.Volume.BitLockerProtection</c>, the same value Explorer uses for the drive's lock
/// icon. Unlike the BitLocker management interfaces, it needs no administrator rights.
/// <see cref="ListFixedDrives"/> lists the same drives without the shell, for a process that
/// has administrator rights.
/// </summary>
[SupportedOSPlatform(MinimumWindows.Platform)]
internal sealed class WindowsDriveEncryptionProbe : IDriveEncryptionProbe
{
    private const string What = "Reading the BitLocker state of the drives";
    private const string PropertyName = "System.Volume.BitLockerProtection";

    public unsafe ProbeResult<IReadOnlyList<DriveEncryption>> GetFixedDrives()
    {
        using ComScope com = ComScope.Enter();
        try
        {
            HRESULT found = PInvoke.PSGetPropertyKeyFromName(PropertyName, out PROPERTYKEY key);
            if (found.Failed)
            {
                return WindowsError.FromHResult(found.Value, What);
            }

            var drives = new List<DriveEncryption>();
            foreach ((FixedDrive drive, string root) in FixedDrives())
            {
                // One drive that cannot be read (locked, offline, damaged) must not hide the
                // others, least of all the system drive.
                ProbeResult<int?> value = ReadValueGuarded(root, key);
                drives.Add(value.IsOk
                    ? new DriveEncryption(drive.Drive, drive.IsSystemDrive, DriveEncryption.Interpret(value.Value), value.Value)
                    : new DriveEncryption(
                        drive.Drive,
                        drive.IsSystemDrive,
                        DriveEncryptionState.Unreadable,
                        RawValue: null,
                        Detail: value.Detail ?? $"Windows would not report the state of {drive.Drive} ({value.Status})."));
            }

            return ProbeResult<IReadOnlyList<DriveEncryption>>.Ok(drives);
        }
        catch (Exception exception)
        {
            return WindowsError.FromException(exception, What);
        }
    }

    public ProbeResult<IReadOnlyList<FixedDrive>> ListFixedDrives()
    {
        try
        {
            return ProbeResult<IReadOnlyList<FixedDrive>>.Ok([.. FixedDrives().Select(d => d.Drive)]);
        }
        catch (Exception exception)
        {
            return WindowsError.FromException(exception, "Listing the fixed drives");
        }
    }

    /// <summary>The fixed drives, from the drive list alone (no shell), with each one's root ("C:\").</summary>
    private static IEnumerable<(FixedDrive Drive, string Root)> FixedDrives()
    {
        string systemRoot = Path.GetPathRoot(Environment.SystemDirectory) ?? string.Empty;
        foreach (DriveInfo drive in DriveInfo.GetDrives())
        {
            if (drive.DriveType == DriveType.Fixed)
            {
                bool isSystem = drive.Name.Equals(systemRoot, StringComparison.OrdinalIgnoreCase);
                yield return (new FixedDrive(drive.Name.TrimEnd('\\'), isSystem), drive.Name);
            }
        }
    }

    private static ProbeResult<int?> ReadValueGuarded(string driveRoot, PROPERTYKEY key)
    {
        try
        {
            return ReadValue(driveRoot, key);
        }
        catch (Exception exception)
        {
            return WindowsError.FromException(exception, What);
        }
    }

    /// <summary>Ok(null) means Windows has no value for the drive.</summary>
    private static unsafe ProbeResult<int?> ReadValue(string driveRoot, PROPERTYKEY key)
    {
        IPropertyStore* store = null;
        PROPVARIANT value = default;
        try
        {
            Guid storeId = IPropertyStore.IID_Guid;
            HRESULT opened;
            fixed (char* path = driveRoot)
            {
                opened = PInvoke.SHGetPropertyStoreFromParsingName(
                    path, null, GETPROPERTYSTOREFLAGS.GPS_DEFAULT, &storeId, (void**)&store);
            }

            if (opened.Failed)
            {
                return WindowsError.FromHResult(opened.Value, What);
            }

            store->GetValue(&key, &value);

            VARENUM type = value.Anonymous.Anonymous.vt;
            return type switch
            {
                VARENUM.VT_I4 or VARENUM.VT_INT => WithValue(value.Anonymous.Anonymous.Anonymous.lVal),
                VARENUM.VT_UI4 or VARENUM.VT_UINT => WithValue((int)value.Anonymous.Anonymous.Anonymous.ulVal),
                VARENUM.VT_EMPTY or VARENUM.VT_NULL => ProbeResult<int?>.Ok(null),
                _ => ProbeFailure.Failed($"{What} failed: unexpected value type {(int)type}."),
            };
        }
        finally
        {
            _ = PInvoke.PropVariantClear(ref value);
            if (store is not null)
            {
                store->Release();
            }
        }

        static ProbeResult<int?> WithValue(int number) => ProbeResult<int?>.Ok(number);
    }
}
