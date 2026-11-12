using System.Globalization;

namespace SecReview.Probing;

/// <summary>One object returned by a WMI query: its requested properties by name.</summary>
public sealed class WmiObject
{
    private readonly Dictionary<string, object?> _values;

    public WmiObject(IEnumerable<KeyValuePair<string, object?>> values)
    {
        _values = new Dictionary<string, object?>(values, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>The property as text; null if it is absent, empty in WMI, or not text.</summary>
    public string? Text(string name) => Value(name) as string;

    /// <summary>
    /// The property as a whole number; null if absent or not a number. WMI hands 64-bit
    /// integers over as text, which is parsed here.
    /// </summary>
    public long? Number(string name) => Value(name) switch
    {
        long number => number,
        string text when long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out long parsed) =>
            parsed,
        _ => null,
    };

    /// <summary>The property as true/false; null if absent or not a boolean.</summary>
    public bool? Flag(string name) => Value(name) as bool?;

    /// <summary>The property as a real number; null if absent or not one.</summary>
    public double? Real(string name) => Value(name) as double?;

    /// <summary>The property as a list of numbers; empty if absent or not such a list.</summary>
    public IReadOnlyList<long> Numbers(string name) => Value(name) as IReadOnlyList<long> ?? [];

    /// <summary>The property as a list of texts; empty if absent or not such a list.</summary>
    public IReadOnlyList<string> Texts(string name) => Value(name) as IReadOnlyList<string> ?? [];

    private object? Value(string name) => _values.GetValueOrDefault(name);
}

public interface IWmiProbe
{
    /// <summary>
    /// Reads the named properties of every instance of a WMI class. A namespace or class this
    /// Windows does not have gives <see cref="ProbeStatus.NotSupported"/>; one that needs
    /// administrator rights gives <see cref="ProbeStatus.AccessDenied"/>.
    /// </summary>
    /// <param name="wmiNamespace">For example <c>ROOT\CIMV2</c>.</param>
    /// <param name="className">For example <c>Win32_OperatingSystem</c>.</param>
    /// <param name="properties">The properties to read.</param>
    /// <param name="only">
    /// Reads only the instances whose yes/no property has this value. Some classes are slow or
    /// reach out to the network unless narrowed (local accounts versus every account of a domain).
    /// </param>
    ProbeResult<IReadOnlyList<WmiObject>> Query(
        string wmiNamespace, string className, IReadOnlyList<string> properties, WmiFlagFilter? only = null);
}

/// <summary>Narrows a WMI query to the instances whose yes/no property has the given value.</summary>
/// <param name="Property">The property's name.</param>
/// <param name="Value">The value it must have.</param>
public sealed record WmiFlagFilter(string Property, bool Value);
