using System.Text.Json;
using SecReview.Checks;
using SecReview.Config;
using SecReview.Probing;

namespace SecReview.SupplyChain.Credentials;

/// <summary>
/// Collects what a stored-secrets check finds across several files and turns it into the
/// outcome: fail when a secret was found, "could not check" when nothing was found but a file
/// could not be read, "does not apply" when none of the files exists. A secret's value never
/// gets in here: only what it is for and where it sits.
/// </summary>
internal sealed class SecretFindings
{
    public const string Expected = "Not stored as plain text";

    private readonly List<Finding> _secrets = [];

    /// <summary>Whether any of the files looked for exists.</summary>
    public bool AnyFile { get; private set; }

    /// <summary>The first file that exists but could not be read or understood.</summary>
    public string? Unreadable { get; private set; }

    public int Count => _secrets.Count;

    public void Add(string item, string? where) => _secrets.Add(Finding.Problem(item, "Stored as plain text", Expected, where));

    /// <summary>Records that one of the files exists, and why it could not be used if it could not.</summary>
    public void SawFile(string? problem = null)
    {
        AnyFile = true;
        if (problem is not null)
        {
            Unreadable ??= problem;
        }
    }

    /// <summary>A settings file in one of the text formats; null if absent or unusable (which is recorded).</summary>
    public SettingsFile? Load(IFileProbe files, string path, SettingsFormat format)
    {
        SettingsFile? file = SettingsFiles.Load(files, path, format);
        if (file is null)
        {
            return null;
        }

        AnyFile = true;
        if (file.Root is null)
        {
            Unreadable ??= file.Problem;
            return null;
        }

        return file;
    }

    /// <summary>A JSON file's root object; null if absent, unusable (which is recorded) or not an object.</summary>
    public JsonElement? LoadJson(IFileProbe files, string path)
    {
        JsonElement? json = SettingsFiles.LoadJsonSettings(files, path, out string? problem);
        if (problem is not null)
        {
            AnyFile = true;
            Unreadable ??= problem;
            return null;
        }

        if (json is null)
        {
            return null;
        }

        AnyFile = true;
        return json is { ValueKind: JsonValueKind.Object } ? json : null;
    }

    /// <summary>An XML file's root; null if absent or unusable (which is recorded).</summary>
    public XmlFile? LoadXml(IFileProbe files, string path)
    {
        XmlFile? file = XmlFiles.Load(files, path);
        if (file is null)
        {
            return null;
        }

        AnyFile = true;
        if (file.Root is null)
        {
            Unreadable ??= file.Problem;
            return null;
        }

        return file;
    }

    /// <summary>The check's outcome. <paramref name="what"/> is the plural noun for the summary ("sign-in tokens").</summary>
    public CheckOutcome Outcome(string tool, string what, string notApplicable)
    {
        if (_secrets.Count > 0)
        {
            return CheckOutcome.Fail(
                _secrets.Count == 1 ? $"{tool}: 1 secret is stored as plain text." : $"{tool}: {_secrets.Count} secrets are stored as plain text.",
                _secrets);
        }

        if (Unreadable is not null)
        {
            return CheckOutcome.Error(Unreadable);
        }

        return AnyFile
            ? CheckOutcome.Pass($"{tool}: no {what} are stored as plain text.", Finding.Ok(Wording.UpperFirst(what), "None stored as plain text", Expected))
            : CheckOutcome.NotApplicable(notApplicable);
    }

    /// <summary>
    /// Whether a text is a literal secret: not empty, and not a "${NAME}" reference to a
    /// variable. Nothing looser counts as a reference: a password may well start with "$" or
    /// sit between "%" signs, and most of these tools would not expand it.
    /// </summary>
    public static bool IsLiteral(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        string text = value.Trim();
        bool reference = text.StartsWith("${", StringComparison.Ordinal) && text.IndexOf('}', StringComparison.Ordinal) == text.Length - 1;
        return !reference;
    }

    /// <summary>Whether a scalar in a settings file is a literal secret.</summary>
    public static bool IsLiteral(ConfigNode? node) => node is ConfigScalar { Kind: not ScalarKind.Other } scalar && IsLiteral(scalar.Text);

    /// <summary>A JSON property's text when it is a literal secret; null otherwise.</summary>
    public static bool HasLiteral(JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out JsonElement value) &&
        value.ValueKind == JsonValueKind.String && IsLiteral(value.GetString());

    /// <summary>The host of an address or registry name; never more, since an address may carry a user name.</summary>
    public static string Host(string address)
    {
        string text = address.Trim();
        if (Uri.TryCreate(text, UriKind.Absolute, out Uri? uri) && uri.Host.Length > 0)
        {
            return uri.Host;
        }

        // "registry.example:5000/path" and the like: up to the first slash, without any user part.
        int slash = text.IndexOf('/', StringComparison.Ordinal);
        string host = slash < 0 ? text : text[..slash];
        int at = host.LastIndexOf('@');
        host = at < 0 ? host : host[(at + 1)..];
        return host.Length > 0 && host.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or ':' or '_') ? host : "one address";
    }
}
