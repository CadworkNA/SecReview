using System.Globalization;
using System.Text;

namespace SecReview.Config;

/// <summary>One element of an XML settings file.</summary>
/// <param name="Name">The element's name as written, without any prefix ("ns:name" is "name").</param>
/// <param name="Attributes">Its attributes, in file order, values decoded.</param>
/// <param name="Children">Its child elements, in file order.</param>
/// <param name="Text">The text directly inside it, decoded and trimmed.</param>
/// <param name="Line">The 1-based line its opening tag starts on.</param>
public sealed record MarkupElement(
    string Name, IReadOnlyList<KeyValuePair<string, string>> Attributes, IReadOnlyList<MarkupElement> Children, string Text, int Line)
{
    /// <summary>Whether the element has that name, whatever the letter case.</summary>
    public bool Is(string name) => Name.Equals(name, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// An attribute's value by its exact name; null if it is not there. The tools read
    /// attribute names exactly, so "Value" beside "value" must not be taken for it.
    /// </summary>
    public string? Attribute(string name)
    {
        foreach ((string key, string value) in Attributes)
        {
            if (key.Equals(name, StringComparison.Ordinal))
            {
                return value;
            }
        }

        return null;
    }

    /// <summary>The child elements of that name, whatever its letter case.</summary>
    public IEnumerable<MarkupElement> ChildrenNamed(string name) => Children.Where(child => child.Is(name));

    /// <summary>The first child element of that name; null if there is none.</summary>
    public MarkupElement? Child(string name) => Children.FirstOrDefault(child => child.Is(name));
}

/// <summary>The outcome of reading an XML file: its root element, or the first thing that was not understood.</summary>
public sealed class MarkupFile
{
    private MarkupFile(MarkupElement? root, string? problem, int problemLine)
    {
        Root = root;
        Problem = problem;
        ProblemLine = problemLine;
    }

    public MarkupElement? Root { get; }

    public string? Problem { get; }

    public int ProblemLine { get; }

    public bool IsOk => Root is not null;

    /// <summary>"could not evaluate (line N): reason", for results.</summary>
    public string Describe() => IsOk ? string.Empty : $"could not evaluate (line {ProblemLine}): {Problem}";

    internal static MarkupFile Ok(MarkupElement root) => new(root, null, 0);

    internal static MarkupFile Failed(int line, string problem) => new(null, problem, line);
}

/// <summary>
/// Reads the XML that settings files are written in (NuGet.Config, Maven's settings.xml):
/// elements, attributes, text, comments, CDATA and the five standard entities. A document
/// type, an entity of the file's own or anything else stops the read with the line number,
/// so nothing outside the file is ever looked at and the file is understood in full or not
/// judged at all.
/// </summary>
public static class MarkupReader
{
    private const int MaximumDepth = 64;

    /// <summary>More attributes than any settings file has; keeps the duplicate test cheap.</summary>
    private const int MaximumAttributes = 64;

    public static MarkupFile Read(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        try
        {
            return MarkupFile.Ok(new Parser(text).ReadDocument());
        }
        catch (ConfigSyntaxException problem)
        {
            return MarkupFile.Failed(problem.Line, problem.Message);
        }
#pragma warning disable CA1031 // A reader must answer for every possible file content.
        catch (Exception unexpected)
#pragma warning restore CA1031
        {
            return MarkupFile.Failed(1, $"the file could not be read ({unexpected.GetType().Name})");
        }
    }

    /// <summary>
    /// Undoes the encoding XML uses for characters a name cannot hold: "_x0020_" is a space.
    /// NuGet names credential elements after their source this way.
    /// </summary>
    public static string DecodeName(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        if (!name.Contains("_x", StringComparison.Ordinal))
        {
            return name;
        }

        var decoded = new StringBuilder(name.Length);
        for (int i = 0; i < name.Length; i++)
        {
            if (name[i] == '_' && i + 6 < name.Length && name[i + 1] == 'x' && name[i + 6] == '_' &&
                ushort.TryParse(name.AsSpan(i + 2, 4), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out ushort code))
            {
                decoded.Append((char)code);
                i += 6;
            }
            else
            {
                decoded.Append(name[i]);
            }
        }

        return decoded.ToString();
    }

    /// <summary>An element still being read: what is known of it so far.</summary>
    private sealed class Open(string name, List<KeyValuePair<string, string>> attributes, int line)
    {
        public string Name { get; } = name;

        public List<KeyValuePair<string, string>> Attributes { get; } = attributes;

        public int Line { get; } = line;

        public List<MarkupElement> Children { get; } = [];

        public StringBuilder Text { get; } = new();

        public MarkupElement Close() => new(LocalName(Name), Attributes, Children, Text.ToString().Trim(), Line);
    }

    private static string LocalName(string name) => name[(name.IndexOf(':', StringComparison.Ordinal) + 1)..];

    private sealed class Parser(string text)
    {
        private int _position = text.Length > 0 && text[0] == (char)0xFEFF ? 1 : 0;
        private int _line = 1;

        public MarkupElement ReadDocument()
        {
            var open = new Stack<Open>();
            MarkupElement? root = null;

            while (true)
            {
                if (open.Count == 0)
                {
                    SkipWhitespace();
                }

                if (_position >= text.Length)
                {
                    if (open.Count > 0)
                    {
                        throw Problem("an element is not closed");
                    }

                    return root ?? throw Problem("the file has no content");
                }

                if (text[_position] != '<')
                {
                    if (open.Count == 0)
                    {
                        throw Problem("text outside the root element");
                    }

                    ReadText(open.Peek().Text);
                    continue;
                }

                if (StartsWith("<!--"))
                {
                    SkipPast("-->", "a comment is not closed");
                }
                else if (StartsWith("<?"))
                {
                    SkipPast("?>", "a processing instruction is not closed");
                }
                else if (StartsWith("<![CDATA["))
                {
                    if (open.Count == 0)
                    {
                        throw Problem("text outside the root element");
                    }

                    int start = _position + "<![CDATA[".Length;
                    int end = text.IndexOf("]]>", start, StringComparison.Ordinal);
                    if (end < 0)
                    {
                        throw Problem("a CDATA section is not closed");
                    }

                    open.Peek().Text.Append(text, start, end - start);
                    Advance(end + 3 - _position);
                }
                else if (StartsWith("<!"))
                {
                    // A document type can define entities and point outside the file.
                    throw Problem("a document type or declaration is not read");
                }
                else if (StartsWith("</"))
                {
                    Advance(2);
                    string name = ReadName();
                    SkipWhitespace();
                    Expect('>');
                    if (open.Count == 0 || open.Peek().Name != name)
                    {
                        throw Problem("a closing tag matches nothing that is open");
                    }

                    MarkupElement closed = open.Pop().Close();
                    if (open.Count > 0)
                    {
                        open.Peek().Children.Add(closed);
                    }
                    else
                    {
                        root = closed;
                    }
                }
                else
                {
                    if (open.Count == 0 && root is not null)
                    {
                        throw Problem("a second root element");
                    }

                    int line = _line;
                    Advance(1);
                    string name = ReadName();
                    List<KeyValuePair<string, string>> attributes = ReadAttributes();
                    bool selfClosed = StartsWith("/>");
                    Advance(selfClosed ? 2 : 1);

                    var element = new Open(name, attributes, line);
                    if (!selfClosed)
                    {
                        if (open.Count >= MaximumDepth)
                        {
                            throw Problem("elements are nested too deeply");
                        }

                        open.Push(element);
                    }
                    else if (open.Count > 0)
                    {
                        open.Peek().Children.Add(element.Close());
                    }
                    else
                    {
                        root = element.Close();
                    }
                }
            }
        }

        private ConfigSyntaxException Problem(string problem) => new(_line, problem);

        private bool StartsWith(string marker) => string.CompareOrdinal(text, _position, marker, 0, marker.Length) == 0;

        /// <summary>Moves forward, counting the lines passed.</summary>
        private void Advance(int count)
        {
            int end = Math.Min(text.Length, _position + count);
            for (; _position < end; _position++)
            {
                if (text[_position] == '\n')
                {
                    _line++;
                }
            }
        }

        private void SkipWhitespace()
        {
            while (_position < text.Length && text[_position] is ' ' or '\t' or '\r' or '\n')
            {
                Advance(1);
            }
        }

        private void SkipPast(string end, string problem)
        {
            int found = text.IndexOf(end, _position, StringComparison.Ordinal);
            if (found < 0)
            {
                throw Problem(problem);
            }

            Advance(found + end.Length - _position);
        }

        private void Expect(char c)
        {
            if (_position >= text.Length || text[_position] != c)
            {
                throw Problem($"expected \"{c}\"");
            }

            Advance(1);
        }

        private string ReadName()
        {
            int start = _position;
            while (_position < text.Length && (char.IsLetterOrDigit(text[_position]) || text[_position] is '_' or '-' or '.' or ':'))
            {
                _position++;
            }

            if (_position == start || char.IsDigit(text[start]) || text[start] is '-' or '.')
            {
                throw Problem("expected a name");
            }

            return text[start.._position];
        }

        /// <summary>Reads attributes up to, not past, the ">" or "/>" that ends the tag.</summary>
        private List<KeyValuePair<string, string>> ReadAttributes()
        {
            var attributes = new List<KeyValuePair<string, string>>();
            while (true)
            {
                int before = _position;
                SkipWhitespace();
                if (_position >= text.Length)
                {
                    throw Problem("a tag is not closed");
                }

                if (text[_position] == '>' || StartsWith("/>"))
                {
                    return attributes;
                }

                if (_position == before)
                {
                    throw Problem("expected a space before an attribute");
                }

                string name = LocalName(ReadName());
                SkipWhitespace();
                Expect('=');
                SkipWhitespace();
                if (_position >= text.Length || text[_position] is not ('"' or '\''))
                {
                    throw Problem("an attribute's value is not in quotes");
                }

                char quote = text[_position];
                int start = _position + 1;
                int end = text.IndexOf(quote, start);
                if (end < 0)
                {
                    throw Problem("an attribute's value is not closed");
                }

                string raw = text[start..end];
                if (raw.Contains('<', StringComparison.Ordinal))
                {
                    throw Problem("\"<\" inside an attribute's value");
                }

                if (attributes.Count >= MaximumAttributes)
                {
                    throw Problem("an element has too many attributes");
                }

                if (attributes.Exists(a => a.Key == name))
                {
                    throw Problem("an attribute is written twice");
                }

                attributes.Add(new KeyValuePair<string, string>(name, Decode(raw)));
                Advance(end + 1 - _position);
            }
        }

        /// <summary>Reads text up to the next tag into the element's text.</summary>
        private void ReadText(StringBuilder into)
        {
            int end = text.IndexOf('<', _position);
            if (end < 0)
            {
                end = text.Length;
            }

            into.Append(Decode(text[_position..end]));
            Advance(end - _position);
        }

        /// <summary>Replaces the five standard entities and character codes; anything else is not understood.</summary>
        private string Decode(string raw)
        {
            if (!raw.Contains('&', StringComparison.Ordinal))
            {
                return raw;
            }

            var decoded = new StringBuilder(raw.Length);
            for (int i = 0; i < raw.Length; i++)
            {
                if (raw[i] != '&')
                {
                    decoded.Append(raw[i]);
                    continue;
                }

                int end = raw.IndexOf(';', i);
                if (end < 0 || end - i > 10)
                {
                    throw Problem("\"&\" does not start an entity");
                }

                string entity = raw[(i + 1)..end];
                switch (entity)
                {
                    case "lt": decoded.Append('<'); break;
                    case "gt": decoded.Append('>'); break;
                    case "amp": decoded.Append('&'); break;
                    case "quot": decoded.Append('"'); break;
                    case "apos": decoded.Append('\''); break;
                    default:
                        bool hex = entity.StartsWith("#x", StringComparison.OrdinalIgnoreCase);
                        if (entity.Length < 2 || entity[0] != '#' ||
                            !uint.TryParse(
                                entity.AsSpan(hex ? 2 : 1), hex ? NumberStyles.AllowHexSpecifier : NumberStyles.None, CultureInfo.InvariantCulture, out uint code) ||
                            code is 0 or > 0x10FFFF or (>= 0xD800 and <= 0xDFFF))
                        {
                            throw Problem("an entity this reader does not know");
                        }

                        decoded.Append(char.ConvertFromUtf32((int)code));
                        break;
                }

                i = end;
            }

            return decoded.ToString();
        }
    }
}
