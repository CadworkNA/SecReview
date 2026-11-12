using SecReview.Checks;
using SecReview.Probing;

namespace SecReview.SupplyChain.Variables;

/// <summary>One environment variable that is set for good.</summary>
/// <param name="Name">Its name, as written in the registry.</param>
/// <param name="Value">Its value. Never put into a result: it may be a secret.</param>
/// <param name="Source">Where it is set, for a finding ("your environment variables (NAME)").</param>
internal sealed record PersistentVariable(string Name, string Value, string Source)
{
    public bool Is(string name) => Name.Equals(name, StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// Every environment variable set for good, for the user or for the PC, the user's winning
/// where both set one. Variables set only in a terminal session, a shell profile or a
/// project's <c>.env</c> file cannot be seen from here and are not claimed to be.
/// </summary>
internal static class PersistentVariables
{
    /// <summary>The variables, by name. Returns the outcome when the registry could not be read.</summary>
    public static CheckOutcome? Load(SystemProbes probes, out IReadOnlyList<PersistentVariable> variables)
    {
        variables = [];
        if (PersistentEnvironment.Names(probes.Registry, out IReadOnlyList<string> names) is { } failed)
        {
            return failed;
        }

        var all = new List<PersistentVariable>(names.Count);
        foreach (string name in names)
        {
            if (PersistentEnvironment.Read(probes, name, out string? value, out string? source) is { } unread)
            {
                return unread;
            }

            if (value is not null)
            {
                all.Add(new PersistentVariable(name, value, source!));
            }
        }

        variables = all;
        return null;
    }

    /// <summary>The variable of that name, if it is set to something.</summary>
    public static PersistentVariable? Find(this IReadOnlyList<PersistentVariable> variables, string name) =>
        variables.FirstOrDefault(v => v.Is(name) && v.Value.Trim().Length > 0);
}
