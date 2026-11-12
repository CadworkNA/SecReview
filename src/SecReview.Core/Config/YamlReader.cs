using System.Globalization;
using System.Text;

namespace SecReview.Config;

/// <summary>
/// Reads YAML settings files (pnpm's config.yaml and pnpm-workspace.yaml, Yarn's .yarnrc.yml).
/// It covers the YAML that settings files use: nested mappings and lists by indentation,
/// plain and quoted values, and one-line <c>[a, b]</c> lists and <c>{a: b}</c> mappings.
/// Everything else that YAML allows (anchors, aliases, tags, block text, multi-line values,
/// several documents) stops the read with the line number: a file is either understood in
/// full or not judged at all.
/// </summary>
public static class YamlReader
{
    private const int MaximumDepth = 32;

    public static ConfigFile Read(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        return ConfigFile.From(() => new Parser(text).ReadDocument());
    }

    /// <summary>One line that carries content: its indentation, its text without comment, and its number.</summary>
    private readonly record struct Line(int Indent, string Text, int Number);

    private sealed class Parser
    {
        private readonly List<Line> _lines = [];
        private int _index;

        public Parser(string text)
        {
            string[] raw = text.Split('\n');
            bool sawDocumentStart = false;
            for (int i = 0; i < raw.Length; i++)
            {
                string line = raw[i].TrimEnd('\r');
                int number = i + 1;
                if (i == 0 && line.StartsWith('\uFEFF'))
                {
                    line = line[1..];
                }

                string trimmed = line.Trim();
                if (trimmed.Length == 0 || trimmed[0] == '#')
                {
                    continue;
                }

                if (trimmed is "---" or "...")
                {
                    // One document start before any content is fine; a second document is not read.
                    if (trimmed == "---" && !sawDocumentStart && _lines.Count == 0)
                    {
                        sawDocumentStart = true;
                        continue;
                    }

                    if (trimmed == "..." && raw.Skip(i + 1).All(l => l.Trim().Length == 0 || l.TrimStart().StartsWith('#')))
                    {
                        break;
                    }

                    throw new ConfigSyntaxException(number, "a file with several documents is not read");
                }

                int indent = 0;
                while (indent < line.Length && line[indent] == ' ')
                {
                    indent++;
                }

                if (line[indent] == '\t')
                {
                    throw new ConfigSyntaxException(number, "a tab is used for indentation");
                }

                _lines.Add(new Line(indent, StripComment(line[indent..]).TrimEnd(), number));
            }
        }

        public ConfigMap ReadDocument()
        {
            if (_lines.Count == 0)
            {
                return new ConfigMap(1);
            }

            Line first = _lines[0];
            ConfigNode root = ReadBlock(first.Indent, depth: 0);
            if (_index < _lines.Count)
            {
                throw new ConfigSyntaxException(_lines[_index].Number, "the indentation does not match any level above");
            }

            return root as ConfigMap ?? throw new ConfigSyntaxException(first.Number, "the file is not a set of named settings");
        }

        /// <summary>The mapping or list whose lines all start at <paramref name="indent"/>.</summary>
        private ConfigNode ReadBlock(int indent, int depth)
        {
            if (depth > MaximumDepth)
            {
                throw new ConfigSyntaxException(_lines[_index].Number, "values are nested too deeply");
            }

            return IsListItem(_lines[_index].Text) ? ReadList(indent, depth) : ReadMap(indent, depth);
        }

        private static bool IsListItem(string text) => text == "-" || text.StartsWith("- ", StringComparison.Ordinal);

        private ConfigMap ReadMap(int indent, int depth)
        {
            var map = new ConfigMap(_lines[_index].Number);
            while (_index < _lines.Count && _lines[_index].Indent == indent)
            {
                Line line = _lines[_index];
                if (IsListItem(line.Text))
                {
                    throw new ConfigSyntaxException(line.Number, "a list item where a named setting was expected");
                }

                ReadEntry(map, line.Text, line.Number, indent, depth);
            }

            if (_index < _lines.Count && _lines[_index].Indent > indent)
            {
                throw new ConfigSyntaxException(_lines[_index].Number, "unexpected indentation");
            }

            return map;
        }

        /// <summary>Reads "key: value" (or "key:" with a nested block below) into the map, and moves past it.</summary>
        private void ReadEntry(ConfigMap map, string text, int number, int indent, int depth)
        {
            (string key, string rest) = SplitKey(text, number);
            _index++;

            ConfigNode value;
            if (rest.Length > 0)
            {
                value = ReadInlineValue(rest, number, depth);
                if (_index < _lines.Count && _lines[_index].Indent > indent)
                {
                    throw new ConfigSyntaxException(_lines[_index].Number, "a value continued on the next line is not read");
                }
            }
            else if (_index < _lines.Count && _lines[_index].Indent > indent)
            {
                value = ReadBlock(_lines[_index].Indent, depth + 1);
            }
            else if (_index < _lines.Count && _lines[_index].Indent == indent && IsListItem(_lines[_index].Text))
            {
                // A list may sit at the same indentation as the key it belongs to.
                value = ReadList(indent, depth + 1);
            }
            else
            {
                value = new ConfigScalar("null", ScalarKind.Other, number);
            }

            if (!map.TryAdd(key, value))
            {
                throw new ConfigSyntaxException(number, $"\"{key}\" is defined twice");
            }
        }

        private ConfigList ReadList(int indent, int depth)
        {
            // A list under a key at the key's own indentation gets here without passing ReadBlock.
            if (depth > MaximumDepth)
            {
                throw new ConfigSyntaxException(_lines[_index].Number, "values are nested too deeply");
            }

            int start = _lines[_index].Number;
            var items = new List<ConfigNode>();
            while (_index < _lines.Count && _lines[_index].Indent == indent && IsListItem(_lines[_index].Text))
            {
                Line line = _lines[_index];
                string rest = line.Text.Length > 1 ? line.Text[2..].TrimStart() : string.Empty;

                // Where the item's own text starts, for anything nested under it.
                int itemIndent = indent + (line.Text.Length - rest.Length);

                if (rest.Length == 0)
                {
                    _index++;
                    items.Add(_index < _lines.Count && _lines[_index].Indent > indent
                        ? ReadBlock(_lines[_index].Indent, depth + 1)
                        : new ConfigScalar("null", ScalarKind.Other, line.Number));
                }
                else if (IsListItem(rest))
                {
                    throw new ConfigSyntaxException(line.Number, "a list written inside a list item on one line is not read");
                }
                else if (LooksLikeEntry(rest))
                {
                    // "- key: value": a mapping whose first entry is on the item's line.
                    var map = new ConfigMap(line.Number);
                    ReadEntry(map, rest, line.Number, itemIndent, depth + 1);
                    while (_index < _lines.Count && _lines[_index].Indent == itemIndent && !IsListItem(_lines[_index].Text))
                    {
                        Line more = _lines[_index];
                        ReadEntry(map, more.Text, more.Number, itemIndent, depth + 1);
                    }

                    if (_index < _lines.Count && _lines[_index].Indent > indent && _lines[_index].Indent != itemIndent)
                    {
                        throw new ConfigSyntaxException(_lines[_index].Number, "unexpected indentation");
                    }

                    items.Add(map);
                }
                else
                {
                    _index++;
                    items.Add(ReadInlineValue(rest, line.Number, depth + 1));
                    if (_index < _lines.Count && _lines[_index].Indent > indent)
                    {
                        throw new ConfigSyntaxException(_lines[_index].Number, "a value continued on the next line is not read");
                    }
                }
            }

            return new ConfigList(items, start);
        }

        /// <summary>Whether the text is "key: value" or "key:" rather than a plain value.</summary>
        private static bool LooksLikeEntry(string text)
        {
            if (text[0] is '[' or '{')
            {
                return false;
            }

            int colon = FindKeyEnd(text);
            return colon >= 0;
        }

        /// <summary>The position of the colon that ends the key, or -1 if the text has none.</summary>
        private static int FindKeyEnd(string text)
        {
            if (text[0] is '"' or '\'')
            {
                int close = FindClosingQuote(text, 0);
                int after = close + 1;
                return close > 0 && after < text.Length && text[after] == ':' && (after + 1 == text.Length || text[after + 1] == ' ')
                    ? after
                    : -1;
            }

            for (int i = 0; i < text.Length; i++)
            {
                if (text[i] == ':' && (i + 1 == text.Length || text[i + 1] == ' '))
                {
                    return i;
                }
            }

            return -1;
        }

        private static (string Key, string Value) SplitKey(string text, int number)
        {
            if (text[0] is '?' or '&' or '*' or '!' or '|' or '>' or '%' or '@' or '`')
            {
                throw new ConfigSyntaxException(number, $"\"{text[0]}\" starts something this reader does not read");
            }

            int colon = FindKeyEnd(text);
            if (colon < 0)
            {
                throw new ConfigSyntaxException(number, "expected \"name: value\"");
            }

            string rawKey = text[..colon].TrimEnd();
            string key = rawKey.Length > 0 && rawKey[0] is '"' or '\''
                ? Unquote(rawKey, number)
                : rawKey;
            if (key == "<<")
            {
                throw new ConfigSyntaxException(number, "merge keys are not read");
            }

            if (key.Length == 0)
            {
                throw new ConfigSyntaxException(number, "a setting has no name");
            }

            return (key, text[(colon + 1)..].Trim());
        }

        /// <summary>A value written on one line: quoted, plain, or a one-line list or mapping.</summary>
        private static ConfigNode ReadInlineValue(string text, int number, int depth)
        {
            int position = 0;
            ConfigNode value = ReadFlowValue(text, ref position, number, depth, insideFlow: false);
            if (text.AsSpan(position).Trim().Length > 0)
            {
                throw new ConfigSyntaxException(number, "unexpected text after a value");
            }

            return value;
        }

        private static ConfigNode ReadFlowValue(string text, ref int position, int number, int depth, bool insideFlow)
        {
            if (depth > MaximumDepth)
            {
                throw new ConfigSyntaxException(number, "values are nested too deeply");
            }

            SkipSpaces(text, ref position);
            if (position >= text.Length)
            {
                return new ConfigScalar("null", ScalarKind.Other, number);
            }

            char first = text[position];
            if (first == '[')
            {
                position++;
                var items = new List<ConfigNode>();
                while (true)
                {
                    SkipSpaces(text, ref position);
                    if (position >= text.Length)
                    {
                        throw new ConfigSyntaxException(number, "a list is not closed on its line");
                    }

                    if (text[position] == ']')
                    {
                        position++;
                        return new ConfigList(items, number);
                    }

                    items.Add(ReadFlowValue(text, ref position, number, depth + 1, insideFlow: true));
                    SkipSpaces(text, ref position);
                    if (position < text.Length && text[position] == ',')
                    {
                        position++;
                    }
                    else if (position >= text.Length || text[position] != ']')
                    {
                        throw new ConfigSyntaxException(number, "expected \",\" or \"]\" in a list");
                    }
                }
            }

            if (first == '{')
            {
                position++;
                var map = new ConfigMap(number);
                while (true)
                {
                    SkipSpaces(text, ref position);
                    if (position >= text.Length)
                    {
                        throw new ConfigSyntaxException(number, "a mapping is not closed on its line");
                    }

                    if (text[position] == '}')
                    {
                        position++;
                        return map;
                    }

                    string key = ReadFlowKey(text, ref position, number);
                    ConfigNode value = ReadFlowValue(text, ref position, number, depth + 1, insideFlow: true);
                    if (!map.TryAdd(key, value))
                    {
                        throw new ConfigSyntaxException(number, $"\"{key}\" is defined twice");
                    }

                    SkipSpaces(text, ref position);
                    if (position < text.Length && text[position] == ',')
                    {
                        position++;
                    }
                    else if (position >= text.Length || text[position] != '}')
                    {
                        throw new ConfigSyntaxException(number, "expected \",\" or \"}\" in a mapping");
                    }
                }
            }

            if (first is '"' or '\'')
            {
                int close = FindClosingQuote(text, position);
                if (close < 0)
                {
                    throw new ConfigSyntaxException(number, "a quoted value is not closed on its line");
                }

                string quoted = Unquote(text[position..(close + 1)], number);
                position = close + 1;
                return new ConfigScalar(quoted, ScalarKind.Text, number);
            }

            if (first is '&' or '*' or '!' or '|' or '>' or '%' or '@' or '`')
            {
                throw new ConfigSyntaxException(number, $"\"{first}\" starts something this reader does not read");
            }

            // A plain value: to the end of the line, or to the next separator inside [ ] or { }.
            int start = position;
            while (position < text.Length && !(insideFlow && text[position] is ',' or ']' or '}'))
            {
                position++;
            }

            return Plain(text[start..position].Trim(), number);
        }

        private static string ReadFlowKey(string text, ref int position, int number)
        {
            SkipSpaces(text, ref position);
            string key;
            if (text[position] is '"' or '\'')
            {
                int close = FindClosingQuote(text, position);
                if (close < 0)
                {
                    throw new ConfigSyntaxException(number, "a quoted name is not closed on its line");
                }

                key = Unquote(text[position..(close + 1)], number);
                position = close + 1;
            }
            else
            {
                int start = position;
                while (position < text.Length && text[position] is not (':' or ',' or '}' or '{' or '['))
                {
                    position++;
                }

                key = text[start..position].Trim();
            }

            SkipSpaces(text, ref position);
            if (key.Length == 0 || position >= text.Length || text[position] != ':')
            {
                throw new ConfigSyntaxException(number, "expected \"name: value\" in a mapping");
            }

            position++;
            return key;
        }

        private static ConfigScalar Plain(string text, int number)
        {
            if (text.Length == 0 || text is "~" or "null" or "Null" or "NULL")
            {
                return new ConfigScalar("null", ScalarKind.Other, number);
            }

            if (text is "true" or "True" or "TRUE" or "false" or "False" or "FALSE")
            {
                return new ConfigScalar(text.ToLowerInvariant(), ScalarKind.Boolean, number);
            }

            if (long.TryParse(text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out _) &&
                (text.TrimStart('+', '-') == "0" || text.TrimStart('+', '-')[0] != '0'))
            {
                return new ConfigScalar(text, ScalarKind.Number, number);
            }

            // Digits with a leading zero ("0755") are a number in one YAML version and octal in
            // another; they are kept as the text that was written.
            if (text.TrimStart('+', '-').All(char.IsAsciiDigit))
            {
                return new ConfigScalar(text, ScalarKind.Text, number);
            }

            // Decimal numbers and the like are YAML numbers too; they are kept as written.
            if (double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out _) && text.Any(char.IsAsciiDigit))
            {
                return new ConfigScalar(text, ScalarKind.Other, number);
            }

            return new ConfigScalar(text, ScalarKind.Text, number);
        }

        private static void SkipSpaces(string text, ref int position)
        {
            while (position < text.Length && text[position] == ' ')
            {
                position++;
            }
        }

        /// <summary>The index of the quote that closes the one at <paramref name="start"/>, or -1.</summary>
        private static int FindClosingQuote(string text, int start)
        {
            char quote = text[start];
            for (int i = start + 1; i < text.Length; i++)
            {
                if (quote == '"' && text[i] == '\\')
                {
                    i++;
                }
                else if (text[i] == quote)
                {
                    if (quote == '\'' && i + 1 < text.Length && text[i + 1] == '\'')
                    {
                        i++;
                    }
                    else
                    {
                        return i;
                    }
                }
            }

            return -1;
        }

        private static string Unquote(string quoted, int number)
        {
            string body = quoted[1..^1];
            if (quoted[0] == '\'')
            {
                return body.Replace("''", "'", StringComparison.Ordinal);
            }

            var text = new StringBuilder(body.Length);
            for (int i = 0; i < body.Length; i++)
            {
                if (body[i] != '\\')
                {
                    text.Append(body[i]);
                    continue;
                }

                if (++i >= body.Length)
                {
                    throw new ConfigSyntaxException(number, "a quoted value ends in the middle of an escape");
                }

                switch (body[i])
                {
                    case 'n': text.Append('\n'); break;
                    case 't': text.Append('\t'); break;
                    case 'r': text.Append('\r'); break;
                    case '0': text.Append('\0'); break;
                    case '"': text.Append('"'); break;
                    case '/': text.Append('/'); break;
                    case '\\': text.Append('\\'); break;
                    case ' ': text.Append(' '); break;
                    case 'x' or 'u' or 'U':
                        int digits = body[i] switch { 'x' => 2, 'u' => 4, _ => 8 };
                        if (body.Length - i - 1 < digits ||
                            !uint.TryParse(body.AsSpan(i + 1, digits), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out uint code) ||
                            code > 0x10FFFF || (code is >= 0xD800 and <= 0xDFFF))
                        {
                            throw new ConfigSyntaxException(number, "a quoted value has an invalid character code");
                        }

                        text.Append(char.ConvertFromUtf32((int)code));
                        i += digits;
                        break;
                    default:
                        throw new ConfigSyntaxException(number, $"\"\\{body[i]}\" is not an escape this reader knows");
                }
            }

            return text.ToString();
        }

        /// <summary>Removes a trailing comment: a "#" outside quotes that starts the text or follows a space.</summary>
        private static string StripComment(string text)
        {
            char quote = '\0';
            for (int i = 0; i < text.Length; i++)
            {
                char c = text[i];
                if (quote != '\0')
                {
                    if (quote == '"' && c == '\\')
                    {
                        i++;
                    }
                    else if (c == quote)
                    {
                        quote = '\0';
                    }
                }
                else if (c is '"' or '\'' && (i == 0 || text[i - 1] is ' ' or ':' or '[' or '{' or ',' or '-'))
                {
                    quote = c;
                }
                else if (c == '#' && (i == 0 || text[i - 1] == ' '))
                {
                    return text[..i];
                }
            }

            return text;
        }
    }
}
