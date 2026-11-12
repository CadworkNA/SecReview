using System.Runtime.Versioning;
using Microsoft.Win32;

namespace SecReview.Probing.Windows;

/// <summary>Reads the registry, read-only, always through the 64-bit view.</summary>
[SupportedOSPlatform(MinimumWindows.Platform)]
internal sealed class WindowsRegistryProbe : IRegistryProbe
{
    private const string What = "Reading the registry";

    public ProbeResult<RegistryValue> GetValue(RegistryRoot root, string keyPath, string valueName) =>
        Read<RegistryValue>(root, keyPath, key =>
        {
            object? data = key.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            if (data is null)
            {
                return ProbeFailure.NotFound();
            }

            return ProbeResult<RegistryValue>.Ok(key.GetValueKind(valueName) switch
            {
                // The runtime hands REG_DWORD back as a signed int; the registry means unsigned.
                RegistryValueKind.DWord => RegistryValue.FromNumber(unchecked((uint)(int)data)),
                RegistryValueKind.QWord => RegistryValue.FromNumber((long)data),
                RegistryValueKind.String or RegistryValueKind.ExpandString => RegistryValue.FromText((string)data),
                RegistryValueKind.MultiString => RegistryValue.FromTextList((string[])data),
                RegistryValueKind.Binary => RegistryValue.FromBinary((byte[])data),
                _ => RegistryValue.Other,
            });
        });

    public ProbeResult<IReadOnlyList<string>> GetSubKeyNames(RegistryRoot root, string keyPath) =>
        Read<IReadOnlyList<string>>(root, keyPath, key => ProbeResult<IReadOnlyList<string>>.Ok(key.GetSubKeyNames()));

    public ProbeResult<IReadOnlyList<string>> GetValueNames(RegistryRoot root, string keyPath) =>
        Read<IReadOnlyList<string>>(root, keyPath, key => ProbeResult<IReadOnlyList<string>>.Ok(key.GetValueNames()));

    private static ProbeResult<T> Read<T>(RegistryRoot root, string keyPath, Func<RegistryKey, ProbeResult<T>> read)
    {
        try
        {
            RegistryHive hive = root == RegistryRoot.CurrentUser ? RegistryHive.CurrentUser : RegistryHive.LocalMachine;
            using RegistryKey baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            using RegistryKey? key = baseKey.OpenSubKey(keyPath, writable: false);
            return key is null ? ProbeFailure.NotFound() : read(key);
        }
        catch (Exception exception)
        {
            return WindowsError.FromException(exception, What);
        }
    }
}
