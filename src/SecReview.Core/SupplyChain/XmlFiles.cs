using SecReview.Config;
using SecReview.Probing;

namespace SecReview.SupplyChain;

/// <summary>
/// An XML settings file that exists: its contents, or why they could not be used. As with the
/// other formats, a file is understood in full or not judged at all.
/// </summary>
/// <param name="Path">The full path.</param>
/// <param name="Root">The root element; null when <paramref name="Problem"/> is set.</param>
/// <param name="Problem">Why the file could not be used, in words fit for a result.</param>
internal sealed record XmlFile(string Path, MarkupElement? Root, string? Problem)
{
    /// <summary>The file's name without its folder.</summary>
    public string Name => Path[(Path.LastIndexOf('\\') + 1)..];

    /// <summary>"path, line N", for a finding's source.</summary>
    public string At(MarkupElement element) => $"{Path}, line {element.Line}";
}

/// <summary>Reads XML settings files through the file probe. Nothing outside the file is ever fetched.</summary>
internal static class XmlFiles
{
    /// <summary>The file at a path; null if there is no such file.</summary>
    public static XmlFile? Load(IFileProbe files, string path)
    {
        ProbeResult<string> text = files.ReadText(path);
        if (text.Status == ProbeStatus.NotFound)
        {
            return null;
        }

        string name = path[(path.LastIndexOf('\\') + 1)..];
        if (!text.IsOk)
        {
            return new XmlFile(
                path, null, text.Status == ProbeStatus.AccessDenied ? $"{name} could not be read: access denied." : $"{name} could not be read: {text.Detail}");
        }

        MarkupFile parsed = MarkupReader.Read(text.Value!);
        return parsed.IsOk ? new XmlFile(path, parsed.Root, null) : new XmlFile(path, null, $"{name}: {parsed.Describe()}");
    }
}
