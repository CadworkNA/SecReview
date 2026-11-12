using System.Text;
using SecReview.Config;

namespace SecReview.Tests.Config;

internal static class ConfigTesting
{
    /// <summary>
    /// A value as compact text for assertions: text in quotes, numbers and booleans bare,
    /// other scalars in angle brackets, lists in [ ], maps in { }.
    /// </summary>
    public static string Render(this ConfigNode? node)
    {
        var text = new StringBuilder();
        Write(node, text);
        return text.ToString();
    }

    /// <summary>The whole file, or "FAILED line N: problem".</summary>
    public static string Render(this ConfigFile file) =>
        file.IsOk ? file.Root.Render() : $"FAILED line {file.ProblemLine}: {file.Problem}";

    private static void Write(ConfigNode? node, StringBuilder text)
    {
        switch (node)
        {
            case null:
                text.Append("(none)");
                break;
            case ConfigScalar scalar:
                text.Append(scalar.Kind switch
                {
                    ScalarKind.Text => $"\"{scalar.Text}\"",
                    ScalarKind.Other => $"<{scalar.Text}>",
                    _ => scalar.Text,
                });
                break;
            case ConfigList list:
                text.Append('[');
                for (int i = 0; i < list.Items.Count; i++)
                {
                    if (i > 0)
                    {
                        text.Append(", ");
                    }

                    Write(list.Items[i], text);
                }

                text.Append(']');
                break;
            case ConfigMap map:
                text.Append('{');
                for (int i = 0; i < map.Entries.Count; i++)
                {
                    if (i > 0)
                    {
                        text.Append(", ");
                    }

                    text.Append(map.Entries[i].Key).Append('=');
                    Write(map.Entries[i].Value, text);
                }

                text.Append('}');
                break;
        }
    }

    /// <summary>
    /// One to three random changes to a text: a character replaced, removed, inserted, a piece
    /// doubled, or the text cut short.
    /// </summary>
    public static string Damage(string text, Random random)
    {
        var damaged = new StringBuilder(text);
        int changes = random.Next(1, 4);
        for (int i = 0; i < changes && damaged.Length > 0; i++)
        {
            int at = random.Next(damaged.Length);
            switch (random.Next(5))
            {
                case 0:
                    damaged[at] = Interesting(random);
                    break;
                case 1:
                    damaged.Remove(at, 1);
                    break;
                case 2:
                    damaged.Insert(at, Interesting(random));
                    break;
                case 3:
                    damaged.Length = at;
                    break;
                default:
                    damaged.Insert(at, damaged.ToString(at, Math.Min(random.Next(1, 30), damaged.Length - at)));
                    break;
            }
        }

        return damaged.ToString();
    }

    /// <summary>A character likely to matter to a parser, or any printable one.</summary>
    private static char Interesting(Random random)
    {
        const string Special = "\"'[]{}=:#,.-\\\n\r\t &*!|>%@`?;_";
        return random.Next(3) == 0 ? (char)random.Next(32, 127) : Special[random.Next(Special.Length)];
    }
}
