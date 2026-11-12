namespace SecReview.Probing;

public enum RegistryRoot
{
    /// <summary>HKEY_LOCAL_MACHINE, 64-bit view.</summary>
    LocalMachine,

    /// <summary>HKEY_CURRENT_USER of the user the process runs as.</summary>
    CurrentUser,
}

public enum RegistryValueType
{
    /// <summary>REG_DWORD or REG_QWORD.</summary>
    Number,

    /// <summary>REG_SZ or REG_EXPAND_SZ (not expanded).</summary>
    Text,

    /// <summary>REG_MULTI_SZ.</summary>
    TextList,

    /// <summary>REG_BINARY.</summary>
    Binary,

    /// <summary>Any other type; the data is not read.</summary>
    Other,
}

/// <summary>A registry value. Only the member matching <see cref="Type"/> is meaningful.</summary>
public sealed class RegistryValue
{
    private RegistryValue(RegistryValueType type, long number, string? text, IReadOnlyList<string>? list, byte[]? binary)
    {
        Type = type;
        Number = number;
        Text = text ?? string.Empty;
        TextList = list ?? [];
        Binary = binary ?? [];
    }

    public RegistryValueType Type { get; }

    public long Number { get; }

    public string Text { get; }

    public IReadOnlyList<string> TextList { get; }

    public ReadOnlyMemory<byte> Binary { get; }

    public static RegistryValue FromNumber(long value) => new(RegistryValueType.Number, value, null, null, null);

    public static RegistryValue FromText(string value) => new(RegistryValueType.Text, 0, value, null, null);

    public static RegistryValue FromTextList(IReadOnlyList<string> value) =>
        new(RegistryValueType.TextList, 0, null, value, null);

    public static RegistryValue FromBinary(byte[] value) => new(RegistryValueType.Binary, 0, null, null, value);

    public static RegistryValue Other { get; } = new(RegistryValueType.Other, 0, null, null, null);
}

public interface IRegistryProbe
{
    /// <summary>
    /// Reads one value. <see cref="ProbeStatus.NotFound"/> when the key or the value does not
    /// exist, which for a policy setting means "not configured".
    /// </summary>
    ProbeResult<RegistryValue> GetValue(RegistryRoot root, string keyPath, string valueName);

    /// <summary>Names of the keys directly under a key.</summary>
    ProbeResult<IReadOnlyList<string>> GetSubKeyNames(RegistryRoot root, string keyPath);

    /// <summary>Names of the values in a key.</summary>
    ProbeResult<IReadOnlyList<string>> GetValueNames(RegistryRoot root, string keyPath);
}
