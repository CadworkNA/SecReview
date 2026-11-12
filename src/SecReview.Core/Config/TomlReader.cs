using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace SecReview.Config;

/// <summary>
/// Reads TOML settings files (uv.toml, bunfig.toml, Poetry and PDM config.toml, pyproject.toml).
/// It covers the TOML that settings files use: tables, arrays of tables, dotted and quoted
/// keys, strings of all four kinds, numbers, booleans, dates, arrays and inline tables.
/// Anything else, and anything malformed, stops the read with the line number: a file is
/// either understood in full or not judged at all.
/// </summary>
public static partial class TomlReader
{
    /// <summary>Deeper nesting than any real settings file has; a limit keeps hostile input from exhausting the stack.</summary>
    private const int MaximumDepth = 32;

    /// <summary>
    /// The bare TOML values that are neither whole decimal numbers nor booleans: decimal
    /// numbers, infinity and not-a-number, hexadecimal, octal and binary numbers, dates, times
    /// and dates with times.
    /// </summary>
    [GeneratedRegex(
        @"^(?:[+-]?(?:0|[1-9][0-9_]*)(?:\.[0-9][0-9_]*)?(?:[eE][+-]?[0-9][0-9_]*)?" +
        @"|[+-]?(?:inf|nan)" +
        @"|0x[0-9A-Fa-f][0-9A-Fa-f_]*|0o[0-7][0-7_]*|0b[01][01_]*" +
        @"|[0-9]{2}:[0-9]{2}(?::[0-9]{2}(?:\.[0-9]+)?)?" +
        @"|[0-9]{4}-[0-9]{2}-[0-9]{2}(?:[Tt ][0-9]{2}:[0-9]{2}(?::[0-9]{2}(?:\.[0-9]+)?)?(?:[Zz]|[+-][0-9]{2}:[0-9]{2})?)?)$",
        RegexOptions.CultureInvariant,
        matchTimeoutMilliseconds: 250)]
    private static partial Regex OtherValue();

    public static ConfigFile Read(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        return ConfigFile.From(() => new Parser(text).ReadDocument());
    }

    private sealed class Parser(string text)
    {
        private readonly string _text = text;

        /// <summary>Tables that were defined with a [header] or as a value, which may not be defined again.</summary>
        private readonly HashSet<ConfigMap> _closed = new(ReferenceEqualityComparer.Instance);

        private int _position;
        private int _line = 1;

        public ConfigMap ReadDocument()
        {
            var root = new ConfigMap(1);
            ConfigMap current = root;

            while (true)
            {
                SkipBlankAndComments();
                if (AtEnd)
                {
                    return root;
                }

                if (Peek == '[')
                {
                    current = ReadTableHeader(root);
                }
                else
                {
                    ReadKeyValue(current, depth: 0);
                }

                SkipSpaces();
                SkipComment();
                if (!AtEnd && !TryReadNewline())
                {
                    throw Fail("unexpected text after a value");
                }
            }
        }

        private bool AtEnd => _position >= _text.Length;

        private char Peek => _text[_position];

        private ConfigSyntaxException Fail(string problem) => new(_line, problem);

        private bool TryReadNewline()
        {
            if (AtEnd)
            {
                return false;
            }

            if (Peek == '\n')
            {
                _position++;
                _line++;
                return true;
            }

            if (Peek == '\r' && _position + 1 < _text.Length && _text[_position + 1] == '\n')
            {
                _position += 2;
                _line++;
                return true;
            }

            return false;
        }

        private void SkipSpaces()
        {
            while (!AtEnd && Peek is ' ' or '\t')
            {
                _position++;
            }
        }

        private void SkipComment()
        {
            if (!AtEnd && Peek == '#')
            {
                while (!AtEnd && Peek is not ('\n' or '\r'))
                {
                    _position++;
                }
            }
        }

        private void SkipBlankAndComments()
        {
            while (true)
            {
                SkipSpaces();
                SkipComment();
                if (!TryReadNewline())
                {
                    return;
                }
            }
        }

        /// <summary>[a.b] or [[a.b]]: returns the table that the following keys go into.</summary>
        private ConfigMap ReadTableHeader(ConfigMap root)
        {
            int line = _line;
            _position++;
            bool isArray = !AtEnd && Peek == '[';
            if (isArray)
            {
                _position++;
            }

            List<string> path = ReadKeyPath();
            Expect(']');
            if (isArray)
            {
                Expect(']');
            }

            ConfigMap parent = Descend(root, path.GetRange(0, path.Count - 1), line);
            string name = path[^1];
            ConfigNode? existing = parent[name];

            if (isArray)
            {
                var table = new ConfigMap(line);
                switch (existing)
                {
                    case null:
                        parent.TryAdd(name, ConfigList.Growable(table, line));
                        break;
                    case ConfigList list when !_closedLists.Contains(list) && list.TryAppend(table):
                        break;
                    default:
                        throw new ConfigSyntaxException(line, $"\"{name}\" is defined twice");
                }

                return table;
            }

            if (existing is null)
            {
                var table = new ConfigMap(line);
                parent.TryAdd(name, table);
                _closed.Add(table);
                return table;
            }

            // A table may be opened once; one that only exists because [a.b] came first may still be opened as [a].
            if (existing is ConfigMap map && _closed.Add(map))
            {
                return map;
            }

            throw new ConfigSyntaxException(line, $"\"{name}\" is defined twice");
        }

        /// <summary>Arrays written as values ([1, 2]) can never be extended with [[name]].</summary>
        private readonly HashSet<ConfigList> _closedLists = new(ReferenceEqualityComparer.Instance);

        /// <summary>Walks to the table at a path, creating tables on the way; inside an array of tables, the last one.</summary>
        private static ConfigMap Descend(ConfigMap from, List<string> path, int line)
        {
            ConfigMap current = from;
            foreach (string key in path)
            {
                switch (current[key])
                {
                    case null:
                        var created = new ConfigMap(line);
                        current.TryAdd(key, created);
                        current = created;
                        break;
                    case ConfigMap map:
                        current = map;
                        break;
                    case ConfigList { Items: [.., ConfigMap last] }:
                        current = last;
                        break;
                    default:
                        throw new ConfigSyntaxException(line, $"\"{key}\" is a value, not a table");
                }
            }

            return current;
        }

        private void ReadKeyValue(ConfigMap table, int depth)
        {
            int line = _line;
            List<string> path = ReadKeyPath();
            Expect('=');
            SkipSpaces();
            ConfigNode value = ReadValue(depth);

            ConfigMap target = table;
            foreach (string key in path.GetRange(0, path.Count - 1))
            {
                switch (target[key])
                {
                    case null:
                        var created = new ConfigMap(line);
                        target.TryAdd(key, created);
                        target = created;
                        break;
                    case ConfigMap map when !_closed.Contains(map) || ReferenceEquals(map, table):
                        target = map;
                        break;
                    default:
                        throw new ConfigSyntaxException(line, $"\"{key}\" is defined twice");
                }
            }

            if (!target.TryAdd(path[^1], value))
            {
                throw new ConfigSyntaxException(line, $"\"{path[^1]}\" is defined twice");
            }
        }

        /// <summary>One or more keys separated by dots: bare, "basic" or 'literal'.</summary>
        private List<string> ReadKeyPath()
        {
            var path = new List<string>(2);
            while (true)
            {
                SkipSpaces();
                if (AtEnd)
                {
                    throw Fail("a key is missing");
                }

                if (Peek == '"')
                {
                    path.Add(ReadBasicString(multiLineAllowed: false));
                }
                else if (Peek == '\'')
                {
                    path.Add(ReadLiteralString(multiLineAllowed: false));
                }
                else
                {
                    int start = _position;
                    while (!AtEnd && (char.IsAsciiLetterOrDigit(Peek) || Peek is '_' or '-'))
                    {
                        _position++;
                    }

                    if (_position == start)
                    {
                        throw Fail("a key is missing or has characters that need quotes");
                    }

                    path.Add(_text[start.._position]);
                }

                SkipSpaces();
                if (AtEnd || Peek != '.')
                {
                    return path;
                }

                _position++;
            }
        }

        private void Expect(char expected)
        {
            SkipSpaces();
            if (AtEnd || Peek != expected)
            {
                throw Fail($"expected \"{expected}\"");
            }

            _position++;
        }

        private ConfigNode ReadValue(int depth)
        {
            if (depth > MaximumDepth)
            {
                throw Fail("values are nested too deeply");
            }

            if (AtEnd)
            {
                throw Fail("a value is missing");
            }

            int line = _line;
            switch (Peek)
            {
                case '"':
                    return new ConfigScalar(ReadBasicString(multiLineAllowed: true), ScalarKind.Text, line);
                case '\'':
                    return new ConfigScalar(ReadLiteralString(multiLineAllowed: true), ScalarKind.Text, line);
                case '[':
                    return ReadArray(depth);
                case '{':
                    return ReadInlineTable(depth);
                default:
                    return ReadBareValue();
            }
        }

        private ConfigList ReadArray(int depth)
        {
            int line = _line;
            _position++;
            var items = new List<ConfigNode>();
            while (true)
            {
                SkipBlankAndComments();
                if (AtEnd)
                {
                    throw new ConfigSyntaxException(line, "a list is not closed");
                }

                if (Peek == ']')
                {
                    _position++;
                    break;
                }

                items.Add(ReadValue(depth + 1));
                SkipBlankAndComments();
                if (!AtEnd && Peek == ',')
                {
                    _position++;
                }
                else if (AtEnd || Peek != ']')
                {
                    throw Fail("expected \",\" or \"]\" in a list");
                }
            }

            var list = new ConfigList(items, line);
            _closedLists.Add(list);
            return list;
        }

        private ConfigMap ReadInlineTable(int depth)
        {
            int line = _line;
            _position++;
            var table = new ConfigMap(line);
            SkipSpaces();
            if (!AtEnd && Peek == '}')
            {
                _position++;
                _closed.Add(table);
                return table;
            }

            while (true)
            {
                SkipSpaces();
                ReadKeyValue(table, depth + 1);
                SkipSpaces();
                if (AtEnd)
                {
                    throw new ConfigSyntaxException(line, "an inline table is not closed");
                }

                if (Peek == ',')
                {
                    _position++;
                    continue;
                }

                if (Peek == '}')
                {
                    _position++;
                    _closed.Add(table);
                    return table;
                }

                throw Fail("expected \",\" or \"}\" in an inline table");
            }
        }

        /// <summary>A number, a boolean or a date: everything up to the next separator.</summary>
        private ConfigScalar ReadBareValue()
        {
            int line = _line;
            int start = _position;
            while (!AtEnd && Peek is not (',' or ']' or '}' or '#' or '\n' or '\r'))
            {
                _position++;
            }

            string raw = _text[start.._position].Trim();
            if (raw.Length == 0)
            {
                throw Fail("a value is missing");
            }

            if (raw is "true" or "false")
            {
                return new ConfigScalar(raw, ScalarKind.Boolean, line);
            }

            if (IsInteger(raw))
            {
                return new ConfigScalar(raw, ScalarKind.Number, line);
            }

            // Decimal numbers, other bases, dates and times: valid TOML, kept as written.
            if (OtherValue().IsMatch(raw))
            {
                return new ConfigScalar(raw, ScalarKind.Other, line);
            }

            throw Fail("a value is not valid TOML; text needs quotes");
        }

        private static bool IsInteger(string raw)
        {
            ReadOnlySpan<char> digits = raw.AsSpan();
            if (digits[0] is '+' or '-')
            {
                digits = digits[1..];
            }

            if (digits.Length == 0 || digits[0] == '_' || digits[^1] == '_' || (digits.Length > 1 && digits[0] == '0'))
            {
                return false;
            }

            foreach (char c in digits)
            {
                if (!char.IsAsciiDigit(c) && c != '_')
                {
                    return false;
                }
            }

            return long.TryParse(
                raw.Replace("_", string.Empty, StringComparison.Ordinal), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out _);
        }

        private bool StartsWith(string value) => string.CompareOrdinal(_text, _position, value, 0, value.Length) == 0;

        private string ReadBasicString(bool multiLineAllowed)
        {
            int line = _line;
            if (StartsWith("\"\"\""))
            {
                if (!multiLineAllowed)
                {
                    throw Fail("a key cannot be a multi-line string");
                }

                _position += 3;
                TryReadNewline(); // A newline straight after the opening quotes is not part of the text.
                var lines = new StringBuilder();
                while (true)
                {
                    if (AtEnd)
                    {
                        throw new ConfigSyntaxException(line, "a string is not closed");
                    }

                    if (Peek == '"')
                    {
                        // Three quotes close the string; one or two more before them are text.
                        int run = QuoteRun('"');
                        lines.Append('"', run < 3 ? run : run - 3);
                        _position += run;
                        if (run >= 3)
                        {
                            return lines.ToString();
                        }

                        continue;
                    }

                    if (Peek == '\\')
                    {
                        _position++;
                        if (OnlySpacesUntilNewline())
                        {
                            // A backslash at the end of a line joins it to the next text, dropping the whitespace between.
                            while (!AtEnd && (Peek is ' ' or '\t' || TryReadNewline()))
                            {
                                if (!AtEnd && Peek is ' ' or '\t')
                                {
                                    _position++;
                                }
                            }
                        }
                        else
                        {
                            lines.Append(ReadEscape());
                        }

                        continue;
                    }

                    if (TryReadNewline())
                    {
                        lines.Append('\n');
                        continue;
                    }

                    lines.Append(Peek);
                    _position++;
                }
            }

            _position++;
            var text = new StringBuilder();
            while (true)
            {
                if (AtEnd || Peek is '\n' or '\r')
                {
                    throw new ConfigSyntaxException(line, "a string is not closed");
                }

                char c = Peek;
                _position++;
                if (c == '"')
                {
                    return text.ToString();
                }

                if (c == '\\')
                {
                    text.Append(ReadEscape());
                }
                else
                {
                    text.Append(c);
                }
            }
        }

        /// <summary>How many of the given quote character follow here, counting at most five (two of text and three that close).</summary>
        private int QuoteRun(char quote)
        {
            int count = 0;
            while (_position + count < _text.Length && _text[_position + count] == quote && count < 5)
            {
                count++;
            }

            return count;
        }

        /// <summary>Whether only spaces and tabs stand between here and the end of the line.</summary>
        private bool OnlySpacesUntilNewline()
        {
            int position = _position;
            while (position < _text.Length && _text[position] is ' ' or '\t')
            {
                position++;
            }

            return position < _text.Length && _text[position] is '\n' or '\r';
        }

        private string ReadEscape()
        {
            if (AtEnd)
            {
                throw Fail("a string ends in the middle of an escape");
            }

            char c = Peek;
            _position++;
            switch (c)
            {
                case 'b': return "\b";
                case 't': return "\t";
                case 'n': return "\n";
                case 'f': return "\f";
                case 'r': return "\r";
                case 'e': return "\u001B";
                case '"': return "\"";
                case '\\': return "\\";
                case 'u': return ReadUnicode(4);
                case 'U': return ReadUnicode(8);
                case 'x': return ReadUnicode(2);
                default: throw Fail($"\"\\{c}\" is not a valid escape");
            }
        }

        private string ReadUnicode(int digits)
        {
            if (_position + digits > _text.Length ||
                !uint.TryParse(_text.AsSpan(_position, digits), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out uint code) ||
                code > 0x10FFFF || (code is >= 0xD800 and <= 0xDFFF))
            {
                throw Fail("a string has an invalid character code");
            }

            _position += digits;
            return char.ConvertFromUtf32((int)code);
        }

        private string ReadLiteralString(bool multiLineAllowed)
        {
            int line = _line;
            if (StartsWith("'''"))
            {
                if (!multiLineAllowed)
                {
                    throw Fail("a key cannot be a multi-line string");
                }

                _position += 3;
                TryReadNewline();
                int start = _position;
                int end = _text.IndexOf("'''", start, StringComparison.Ordinal);
                if (end < 0)
                {
                    throw new ConfigSyntaxException(line, "a string is not closed");
                }

                // Three quotes close the string; one or two more before them are text.
                _position = end;
                int run = QuoteRun('\'');
                string body = _text[start..(end + run - 3)];
                _line += body.Count(c => c == '\n');
                _position = end + run;
                return body.Replace("\r\n", "\n", StringComparison.Ordinal);
            }

            _position++;
            int close = _text.IndexOfAny(['\'', '\n', '\r'], _position);
            if (close < 0 || _text[close] != '\'')
            {
                throw new ConfigSyntaxException(line, "a string is not closed");
            }

            string value = _text[_position..close];
            _position = close + 1;
            return value;
        }
    }
}
