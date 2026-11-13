using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecReview.Checks;
using SecReview.Tests.Config;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.Checks;

/// <summary>
/// Makes every check test a mutation test as well. After a test has run a check against its
/// fake PC, the check is run again against damaged copies of that PC: one thing it read (a
/// file, a registry value, an environment variable) is damaged per round, with a seed that
/// depends only on the check and what it read. Whatever the damage, the check must come back
/// with an answer: it must not throw, must not hang, and must say something.
/// </summary>
internal static class DamagedCopies
{
    /// <summary>How long one run of a check on a damaged copy may take before it counts as hung.</summary>
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(30);

    /// <summary>
    /// How many times the usual number of rounds to run. Set the environment variable
    /// SECREVIEW_TEST_DAMAGE to a number for a deeper run than every build can afford.
    /// </summary>
    private static readonly int Depth =
        int.TryParse(Environment.GetEnvironmentVariable("SECREVIEW_TEST_DAMAGE"), out int depth) ? Math.Clamp(depth, 1, 1000) : 1;

    private static readonly JsonDocumentOptions Lenient = new() { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };

    /// <summary>Values to put in the place of any JSON value: every kind, and the awkward ones of each.</summary>
    private static readonly string[] JsonReplacements =
    [
        "null", "true", "false", "0", "-1", "1.5", "1e999", "99999999999999999999", "\"\"", "\"text\"", "\"7 days\"", "\"1\"",
        "\"C:\\\\made-up\\\\..\\\\..\\\\path\"", "\"https://user:made-up@example.test:99999/a b\"", "\"\\u0000\"", "[]", "{}", "[null]",
        "[[], {}, 1, \"a\"]", "{\"a\": {}}", "{\"\": null}",
    ];

    /// <summary>Whole texts to put in the place of a file or value.</summary>
    private static readonly string[] Replacements =
    [
        "", " ", "\n", "\uFEFF", "\0", "{", "[", "null", "[]", "{}", "\"", "=", ":", "- ", "[a", "<a>", "<?xml", "a=b\n[", "\\",
    ];

    /// <summary>Runs <paramref name="check"/> against damaged copies of <paramref name="probes"/>.</summary>
    public static void Verify(ICheck check, FakeProbes probes, TimeProvider clock, bool elevated)
    {
        // A stand-in check written for a test has nothing to prove here.
        if (check.GetType().Assembly != typeof(ICheck).Assembly)
        {
            return;
        }

        var recorder = new Recorder();
        check.Run(new CheckContext(probes.Build(recorder), clock, elevated, CancellationToken.None));
        if (recorder.Read.Count == 0)
        {
            return;
        }

        int rounds = Math.Clamp(recorder.Read.Count * 3, 6, 30) * Depth;
        var random = new Random(Seed(check.Definition.Id, recorder.Read));
        for (int round = 0; round < rounds; round++)
        {
            var damage = new Damage(recorder.Read[round % recorder.Read.Count], random);
            var context = new CheckContext(probes.Build(damage), clock, elevated, CancellationToken.None);

            // On another thread, so that a check that never comes back fails the test rather
            // than stopping the whole run.
            Task<CheckOutcome> run = Task.Run(() => check.Run(context));
            bool finished;
            try
            {
                finished = run.Wait(Limit);
            }
            catch (AggregateException thrown)
            {
                Assert.Fail($"{check.Definition.Id} threw on a damaged copy of {damage.Describe()}\n{thrown.InnerException}");
                return;
            }

            Assert.IsTrue(finished, $"{check.Definition.Id} did not come back within {Limit.TotalSeconds:N0} seconds on a damaged copy of {damage.Describe()}");
            CheckOutcome outcome = run.Result;
            Assert.IsTrue(
                Enum.IsDefined(outcome.Status) && !string.IsNullOrWhiteSpace(outcome.Summary),
                $"{check.Definition.Id} gave no proper answer on a damaged copy of {damage.Describe()}");

            // The summary is one line on screen, in a notification and in a report: whatever
            // was read must not be able to break it up or fill it.
            Assert.IsTrue(
                outcome.Summary.Length <= Wording.MaximumLength && !outcome.Summary.Any(char.IsControl),
                $"{check.Definition.Id} gave a summary that is not one short line ({outcome.Summary.Length} characters) on a damaged copy of {damage.Describe()}");
        }
    }

    /// <summary>
    /// A damaged version of a text. A text that is JSON is half of the time damaged as JSON
    /// (one value replaced by a value of another kind, removed or repeated), which keeps it
    /// well-formed and so reaches the code that walks it.
    /// </summary>
    public static string DamageText(string text, Random random)
    {
        ArgumentNullException.ThrowIfNull(text);
        ArgumentNullException.ThrowIfNull(random);

        switch (random.Next(10))
        {
            case 0:
                return Replacements[random.Next(Replacements.Length)];
            case 1:
                return random.Next(4) switch
                {
                    0 => text.ToUpperInvariant(),
                    1 => text.Replace("\n", "\r\n", StringComparison.Ordinal),
                    2 => text + text,
                    _ => "\uFEFF" + text,
                };
            case < 6 when DamageJson(text, random) is { } json:
                return json;
            default:
                return ConfigTesting.Damage(text, random);
        }
    }

    /// <summary>A text that is JSON with one value changed; null when the text is not JSON.</summary>
    private static string? DamageJson(string text, Random random)
    {
        JsonNode? root;
        try
        {
            root = JsonNode.Parse(text, documentOptions: Lenient);
            var values = new List<JsonNode>();
            Collect(root, values);
            if (root is null || values.Count == 0)
            {
                return null;
            }

            JsonNode target = values[random.Next(values.Count)];
            JsonNode? replacement = JsonNode.Parse(JsonReplacements[random.Next(JsonReplacements.Length)]);
            switch (target.Parent)
            {
                case JsonObject parent:
                    string name = target.GetPropertyName();
                    switch (random.Next(6))
                    {
                        case 0:
                            parent.Remove(name);
                            break;
                        case 1:
                            // The same value under a name that differs only in case, or not at all in what follows.
                            string upper = name.ToUpperInvariant();
                            parent[string.Equals(upper, name, StringComparison.Ordinal) ? name + " " : upper] = target.DeepClone();
                            break;
                        default:
                            parent[name] = replacement;
                            break;
                    }

                    break;
                case JsonArray parent:
                    int index = target.GetElementIndex();
                    if (random.Next(5) == 0)
                    {
                        parent.RemoveAt(index);
                    }
                    else
                    {
                        parent[index] = replacement;
                    }

                    break;
                default:
                    root = replacement;
                    break;
            }

            return root is null ? "null" : root.ToJsonString();
        }
        catch (Exception exception) when (exception is JsonException or ArgumentException or InvalidOperationException)
        {
            return null;
        }
    }

    private static void Collect(JsonNode? node, List<JsonNode> values)
    {
        switch (node)
        {
            case JsonObject map:
                values.Add(map);
                foreach (KeyValuePair<string, JsonNode?> entry in map)
                {
                    Collect(entry.Value, values);
                }

                break;
            case JsonArray list:
                values.Add(list);
                foreach (JsonNode? item in list)
                {
                    Collect(item, values);
                }

                break;
            case not null:
                values.Add(node);
                break;
        }
    }

    /// <summary>The same number on every run and every PC (a text's own hash code is not).</summary>
    private static int Seed(string id, List<string> read)
    {
        uint hash = 2166136261;
        foreach (char c in id.Concat(read.SelectMany(name => name)))
        {
            hash = (hash ^ c) * 16777619;
        }

        return (int)(hash & 0x7FFFFFFF);
    }

    /// <summary>Changes nothing; notes what the check read, in order, each thing once.</summary>
    private sealed class Recorder : ITamper
    {
        private readonly HashSet<string> _seen = new(StringComparer.Ordinal);

        public List<string> Read { get; } = [];

        public string Text(string name, string text)
        {
            Note(name);
            return text;
        }

        public long Number(string name, long number)
        {
            Note(name);
            return number;
        }

        private void Note(string name)
        {
            lock (_seen)
            {
                if (_seen.Add(name))
                {
                    Read.Add(name);
                }
            }
        }
    }

    /// <summary>Damages the one thing named, the same way each time it is read in this round.</summary>
    private sealed class Damage(string target, Random random) : ITamper
    {
        private static readonly long[] Numbers = [0, 1, -1, 2, int.MaxValue, uint.MaxValue, long.MaxValue, long.MinValue, 0x80000000];

        private readonly Lock _gate = new();
        private string? _original;
        private string? _text;
        private long? _number;

        public string Text(string name, string text)
        {
            if (name != target)
            {
                return text;
            }

            lock (_gate)
            {
                _original ??= text;
                return _text ??= DamageText(text, random);
            }
        }

        public long Number(string name, long number)
        {
            if (name != target)
            {
                return number;
            }

            lock (_gate)
            {
                _original ??= number.ToString(System.Globalization.CultureInfo.InvariantCulture);
                return _number ??= Numbers[random.Next(Numbers.Length)];
            }
        }

        /// <summary>What was damaged and into what, for the message of a failed test.</summary>
        public string Describe()
        {
            string now = _text ?? _number?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "(not read in this round)";
            var shown = new StringBuilder();
            foreach (char c in now.Length > 2000 ? now[..2000] : now)
            {
                _ = c is '\n' or '\t' || !char.IsControl(c)
                    ? shown.Append(c)
                    : shown.Append("\\u").Append(((int)c).ToString("x4", System.Globalization.CultureInfo.InvariantCulture));
            }

            return $"{target}.\nIt held:\n{_original}\nDamaged into:\n{shown}";
        }
    }
}
