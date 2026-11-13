using SecReview.Checks;
using SecReview.Config;
using SecReview.Probing;

namespace SecReview.SupplyChain.Credentials;

/// <summary>
/// File transfer tools must not keep server passwords where any program running as the user
/// can read them back. FileZilla and WinSCP encrypt a saved password only when a master
/// password is set; PuTTY keeps a proxy password as written. Only the server's name is
/// shown: never a site's name, a user name or the stored value.
/// </summary>
public sealed class TransferCredentialsCheck : ICheck
{
    public const string Id = "sc.transfer.credentials";

    internal const string PuttySessions = @"Software\SimonTatham\PuTTY\Sessions";
    internal const string WinScpKey = @"Software\Martin Prikryl\WinSCP 2";
    internal const string WinScpSessions = WinScpKey + @"\Sessions";
    internal const string WinScpSecurity = WinScpKey + @"\Configuration\Security";

    private const string MasterPassword = "UseMasterPassword";

    /// <summary>What WinSCP keeps as written, whatever its master password setting.</summary>
    private static readonly string[] WinScpPlain =
        ["PasswordPlain", "ProxyPassword", "TunnelPasswordPlain", "TunnelPassphrasePlain", "EncryptKeyPlain"];

    /// <summary>What WinSCP encrypts only when a master password is set.</summary>
    private static readonly string[] WinScpProtected = ["Password", "ProxyPasswordEnc", "TunnelPassword", "TunnelPassphrase", "EncryptKey"];

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.Medium, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        SystemProbes probes = context.Probes;

        if (CredentialPlaces.Folders(probes, out _, out string roaming) is { } failed)
        {
            return failed;
        }

        var found = new SecretFindings();
        FileZilla(probes.Files, $@"{roaming}\FileZilla\sitemanager.xml", found);
        FileZilla(probes.Files, $@"{roaming}\FileZilla\recentservers.xml", found);
        Putty(probes.Registry, found);
        WinScpRegistry(probes.Registry, found);
        WinScpFile(probes.Files, $@"{roaming}\WinSCP.ini", found);

        return found.Outcome("File transfer tools", "passwords", "No file transfer tool is set up for this user.");
    }

    private static void FileZilla(IFileProbe files, string path, SecretFindings found)
    {
        if (found.LoadXml(files, path) is not { Root: { } root } file)
        {
            return;
        }

        // Sites sit in folders inside folders; the reader has already bounded how deep.
        var open = new Stack<MarkupElement>([root]);
        while (open.TryPop(out MarkupElement? element))
        {
            foreach (MarkupElement child in element.Children)
            {
                open.Push(child);
            }

            // With a master password the value is encrypted ("crypt"). Anything FileZilla
            // writes without one is the password itself, as written or base64-encoded.
            if (element.Is("Server") && element.Child("Pass") is { Text.Length: > 0 } pass &&
                (pass.Attribute("encoding") is not { } encoding || encoding.Equals("base64", StringComparison.OrdinalIgnoreCase)))
            {
                string server = element.Child("Host") is { Text.Length: > 0 } host ? SecretFindings.Host(host.Text) : "one site";
                found.Add($"FileZilla password for {server}", file.At(element));
            }
        }
    }

    private static void Putty(IRegistryProbe registry, SecretFindings found)
    {
        if (SubKeys(registry, PuttySessions, "PuTTY's saved sessions", found) is not { } sessions)
        {
            return;
        }

        foreach (string session in sessions)
        {
            string key = $@"{PuttySessions}\{session}";
            if (HasText(registry, key, "ProxyPassword", "PuTTY's saved sessions", found))
            {
                found.Add($"PuTTY proxy password for {Server(registry, key, "ProxyHost")}", $@"HKCU\{PuttySessions}");
            }
        }
    }

    private static void WinScpRegistry(IRegistryProbe registry, SecretFindings found)
    {
        if (SubKeys(registry, WinScpKey, "WinSCP's settings", found) is null ||
            SubKeys(registry, WinScpSessions, "WinSCP's saved sites", found) is not { } sessions)
        {
            return;
        }

        if (RegistryReader.Number(
                registry, RegistryRoot.CurrentUser, WinScpSecurity, MasterPassword, "WinSCP's master password setting", out long? master) is { } unread)
        {
            // Without it there is no telling whether a saved password is encrypted.
            found.SawFile(unread.Summary);
            return;
        }

        string[] kept = master is 1 ? WinScpPlain : [.. WinScpPlain, .. WinScpProtected];
        foreach (string session in sessions)
        {
            string key = $@"{WinScpSessions}\{session}";
            if (kept.Any(name => HasText(registry, key, name, "WinSCP's saved sites", found)))
            {
                found.Add($"WinSCP password for {Server(registry, key, "HostName")}", $@"HKCU\{WinScpSessions}");
            }
        }
    }

    private static void WinScpFile(IFileProbe files, string path, SecretFindings found)
    {
        if (found.Load(files, path, SettingsFormat.NpmIni) is not { Root: { } root } file)
        {
            return;
        }

        bool master = Section(root, @"Configuration\Security") is { } security && Text(file, security, MasterPassword) == "1";
        string[] kept = master ? WinScpPlain : [.. WinScpPlain, .. WinScpProtected];
        foreach ((string name, ConfigNode node) in root.Entries)
        {
            if (node is ConfigMap session && name.StartsWith(@"Sessions\", StringComparison.OrdinalIgnoreCase) &&
                kept.Any(value => Text(file, session, value) is not null))
            {
                string server = Text(file, session, "HostName") is { } host ? SecretFindings.Host(host) : "one site";
                found.Add($"WinSCP password for {server}", $"{path}, line {session.Line}");
            }
        }
    }

    /// <summary>The keys under a key; null when it is not there or could not be read (which is recorded).</summary>
    private static IReadOnlyList<string>? SubKeys(IRegistryProbe registry, string key, string what, SecretFindings found)
    {
        ProbeResult<IReadOnlyList<string>> names = registry.GetSubKeyNames(RegistryRoot.CurrentUser, key);
        if (names.Status == ProbeStatus.NotFound)
        {
            return null;
        }

        if (!names.IsOk)
        {
            found.SawFile($"Could not read {what}.");
            return null;
        }

        found.SawFile();
        return names.Value!;
    }

    /// <summary>Whether a value holds any text. The text itself goes nowhere.</summary>
    private static bool HasText(IRegistryProbe registry, string key, string name, string what, SecretFindings found)
    {
        ProbeResult<RegistryValue> value = registry.GetValue(RegistryRoot.CurrentUser, key, name);
        if (!value.IsOk && value.Status != ProbeStatus.NotFound)
        {
            found.SawFile($"Could not read {what}.");
        }

        return value.IsOk && value.Value!.Type == RegistryValueType.Text && value.Value.Text.Trim().Length > 0;
    }

    private static string Server(IRegistryProbe registry, string key, string name)
    {
        ProbeResult<RegistryValue> host = registry.GetValue(RegistryRoot.CurrentUser, key, name);
        return host.IsOk && host.Value!.Type == RegistryValueType.Text && host.Value.Text.Trim().Length > 0
            ? SecretFindings.Host(host.Value.Text)
            : "one site";
    }

    /// <summary>A section by its name, whatever the letter case.</summary>
    private static ConfigMap? Section(ConfigMap root, string name) =>
        root.Entries.FirstOrDefault(entry => entry.Key.Equals(name, StringComparison.OrdinalIgnoreCase)).Value as ConfigMap;

    /// <summary>A setting's text in a section; null when it is not there or is empty.</summary>
    private static string? Text(SettingsFile file, ConfigMap section, string name)
    {
        ConfigNode? node = section.Entries.LastOrDefault(entry => entry.Key.Equals(name, StringComparison.OrdinalIgnoreCase)).Value;
        return file.Single(node) is { Text.Length: > 0 } scalar ? scalar.Text : null;
    }
}
