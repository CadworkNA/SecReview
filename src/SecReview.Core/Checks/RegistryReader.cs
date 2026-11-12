using System.Globalization;
using SecReview.Probing;

namespace SecReview.Checks;

/// <summary>
/// Reads registry values for checks. A value that is not there is an answer (null); a value that
/// could not be read is not, and comes back as the outcome the check should end with.
/// </summary>
internal static class RegistryReader
{
    /// <summary>
    /// A number. Numbers stored as text ("1"), as Windows does for some settings, count too.
    /// Returns null when the read worked (the value is null if it is not set), otherwise the
    /// outcome for the failed read.
    /// </summary>
    /// <param name="registry">The registry probe.</param>
    /// <param name="root">Machine or user.</param>
    /// <param name="key">The key path.</param>
    /// <param name="name">The value name.</param>
    /// <param name="what">What is being read, for the message: "the Remote Desktop setting".</param>
    /// <param name="value">The number, or null if the value is not set or is not a number.</param>
    public static CheckOutcome? Number(
        IRegistryProbe registry, RegistryRoot root, string key, string name, string what, out long? value)
    {
        value = null;
        ProbeResult<RegistryValue> result = registry.GetValue(root, key, name);
        if (result.Status == ProbeStatus.NotFound)
        {
            return null;
        }

        if (!result.IsOk)
        {
            return ProbeOutcomes.FromFailure(result, what);
        }

        value = result.Value!.Type switch
        {
            RegistryValueType.Number => result.Value.Number,
            RegistryValueType.Text when long.TryParse(
                result.Value.Text.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out long parsed) => parsed,
            _ => null,
        };
        return null;
    }

    /// <summary>A text value; null when it is not set, is empty or is not text.</summary>
    public static CheckOutcome? Text(
        IRegistryProbe registry, RegistryRoot root, string key, string name, string what, out string? value)
    {
        value = null;
        ProbeResult<RegistryValue> result = registry.GetValue(root, key, name);
        if (result.Status == ProbeStatus.NotFound)
        {
            return null;
        }

        if (!result.IsOk)
        {
            return ProbeOutcomes.FromFailure(result, what);
        }

        if (result.Value!.Type == RegistryValueType.Text && result.Value.Text.Trim().Length > 0)
        {
            value = result.Value.Text.Trim();
        }

        return null;
    }
}
