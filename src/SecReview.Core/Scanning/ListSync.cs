namespace SecReview.Scanning;

/// <summary>
/// Makes a list that is on screen equal to the one wanted with as few changes as possible:
/// what is no longer wanted is removed, what is new is put in place, and what is already where
/// it belongs is left alone. Items are told apart by being the same object, so a row that has
/// not changed is never taken off the screen and put back.
/// </summary>
public static class ListSync
{
    /// <summary>Changes <paramref name="current"/> in place until it equals <paramref name="wanted"/>.</summary>
    /// <returns>How many removals and insertions it took.</returns>
    public static int Apply(IList<object> current, IReadOnlyList<object> wanted)
    {
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(wanted);

        int changes = 0;
        var keep = new HashSet<object>(wanted, ReferenceEqualityComparer.Instance);
        for (int i = current.Count - 1; i >= 0; i--)
        {
            if (!keep.Contains(current[i]))
            {
                current.RemoveAt(i);
                changes++;
            }
        }

        for (int i = 0; i < wanted.Count; i++)
        {
            if (i < current.Count && ReferenceEquals(current[i], wanted[i]))
            {
                continue;
            }

            // Wanted here but further down (or there twice): take it out and put it in place.
            for (int j = i + 1; j < current.Count; j++)
            {
                if (ReferenceEquals(current[j], wanted[i]))
                {
                    current.RemoveAt(j);
                    changes++;
                    break;
                }
            }

            current.Insert(i, wanted[i]);
            changes++;
        }

        while (current.Count > wanted.Count)
        {
            current.RemoveAt(current.Count - 1);
            changes++;
        }

        return changes;
    }
}
