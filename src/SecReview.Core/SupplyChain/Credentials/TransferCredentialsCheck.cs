using SecReview.Checks;
using SecReview.Config;
using SecReview.Probing;
using SecReview.SupplyChain.Scoop;

namespace SecReview.SupplyChain.Credentials;

/// <summary>
/// File transfer tools must not keep server passwords where any program running as the user
/// can read them back. FileZilla and WinSCP encrypt a saved password only when a master
/// password is set; PuTTY keeps a proxy password as written. Only the server's name is
/// shown: never a site's name, a user name or the stored value. Portable copies, which keep
/// their settings beside the program, are looked for in fixed places only (see <see cref="Portable"/>).
/// </summary>
public sealed class TransferCredentialsCheck : ICheck
{
    public const string Id = "sc.transfer.credentials";

    internal const string PuttySessions = @"Software\SimonTatham\PuTTY\Sessions";
    internal const string WinScpKey = @"Software\Martin Prikryl\WinSCP 2";
    internal const string WinScpSessions = WinScpKey + @"\Sessions";
    internal const string WinScpSecurity = WinScpKey + @"\Configuration\Security";

    internal const string WinScpProgram = "WinSCP.exe";
    internal const string WinScpPortable = "WinSCP.ini";
    internal const string FileZillaProgram = "filezilla.exe";
    internal const string FileZillaDefaults = "fzdefaults.xml";

    private const string MasterPassword = "UseMasterPassword";

    /// <summary>The names Scoop's Extras bucket installs these tools under.</summary>
    private static readonly string[] ScoopApps = ["winscp", "filezilla"];

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
        var read = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        FileZillaFolder(probes.Files, $@"{roaming}\FileZilla", found, read);
        Putty(probes.Registry, found);
        WinScpRegistry(probes.Registry, found);
        WinScpFile(probes.Files, $@"{roaming}\{WinScpPortable}", found);
        Portable(probes, found, read);

        return found.Outcome("File transfer tools", "passwords", "No file transfer tool is set up for this user.");
    }

    /// <summary>
    /// Copies that keep their settings beside the program. WinSCP reads a WinSCP.ini there
    /// before anything else; FileZilla reads an fzdefaults.xml there, which can hold sites and
    /// name another settings folder. Only fixed places are looked at, never the whole disk: the
    /// apps Scoop installed, for the user and for everyone, and the folders of the search path.
    /// A folder that cannot be listed is passed over: it is not known to hold either tool.
    /// </summary>
    private static void Portable(SystemProbes probes, SecretFindings found, HashSet<string> read)
    {
        var folders = new List<string>();
        if (ScoopLocator.Locate(probes, out ScoopInstall? scoop) is null && scoop is not null)
        {
            foreach (string root in new[] { scoop.Root, scoop.GlobalRoot })
            {
                folders.AddRange(ScoopApps.Select(name => ScoopLocator.App(probes.Files, root, name)?.Folder).OfType<string>());
            }
        }

        if (SearchPath(probes, out IReadOnlyList<string> path) is { } unread)
        {
            // A password found elsewhere still fails the check; otherwise this is "could not check".
            found.SawFile(unread.Summary);
        }

        folders.AddRange(path);
        foreach (string folder in folders.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            ProbeResult<IReadOnlyList<FileEntry>> entries = probes.Files.List(folder);
            if (!entries.IsOk)
            {
                continue;
            }

            if (Has(entries.Value!, WinScpProgram))
            {
                WinScpFile(probes.Files, $@"{folder}\{WinScpPortable}", found);
            }

            if (Has(entries.Value!, FileZillaProgram))
            {
                FileZillaCopy(probes, folder, found, read);
            }
        }

        static bool Has(IReadOnlyList<FileEntry> entries, string name) =>
            entries.Any(entry => !entry.IsDirectory && entry.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// The folders of the search path as Windows builds it: the PC's, then the user's. Only
    /// full paths on a drive count; network folders are never opened.
    /// </summary>
    private static CheckOutcome? SearchPath(SystemProbes probes, out IReadOnlyList<string> folders)
    {
        folders = [];
        if (RegistryReader.Text(
                probes.Registry, RegistryRoot.LocalMachine, PersistentEnvironment.MachineKey, "Path", "the PC's search path", out string? machine) is { } failed)
        {
            return failed;
        }

        if (RegistryReader.Text(
                probes.Registry, RegistryRoot.CurrentUser, PersistentEnvironment.UserKey, "Path", "your search path", out string? user) is { } failedToo)
        {
            return failedToo;
        }

        folders =
        [
            .. $"{machine};{user}".Split(';')
                .Select(entry => PersistentEnvironment.Expand(entry.Trim().Trim('"'), probes.Environment).Replace('/', '\\').TrimEnd('\\'))
                .Where(entry => entry.Length >= 2 && char.IsAsciiLetter(entry[0]) && entry[1] == ':' && Path.IsPathFullyQualified(entry + '\\')),
        ];
        return null;
    }

    /// <summary>A copy of FileZilla with an fzdefaults.xml beside it: the sites in it, and the settings folder it names.</summary>
    private static void FileZillaCopy(SystemProbes probes, string folder, SecretFindings found, HashSet<string> read)
    {
        if (found.LoadXml(probes.Files, $@"{folder}\{FileZillaDefaults}") is not { Root: { } root } file)
        {
            return;
        }

        FileZillaServers(file, root, found);
        string? location = root.Child("Settings")?.ChildrenNamed("Setting")
            .LastOrDefault(setting => setting.Attribute("name") == "Config Location")?.Text;
        if (string.IsNullOrWhiteSpace(location))
        {
            return;
        }

        if (SettingsFolder(location, folder, probes.Environment) is { } settings)
        {
            FileZillaFolder(probes.Files, settings, found, read);
        }
        else
        {
            found.SawFile("Could not tell where a portable copy of FileZilla keeps its settings.");
        }
    }

    /// <summary>
    /// The folder FileZilla's "Config Location" names. A part of the path that starts with "$"
    /// is an environment variable, one that starts with "$$" is written with one "$", and a
    /// relative path starts beside fzdefaults.xml. Null when a variable is not set or the
    /// result is not a path.
    /// </summary>
    internal static string? SettingsFolder(string location, string beside, IEnvironmentProbe environment)
    {
        var parts = new List<string>();
        foreach (string part in location.Trim().Replace('/', '\\').Split('\\'))
        {
            if (part.StartsWith("$$", StringComparison.Ordinal))
            {
                parts.Add(part[1..]);
            }
            else if (part.StartsWith('$'))
            {
                if (environment.Variable(part[1..]) is not { Length: > 0 } value)
                {
                    return null;
                }

                parts.Add(value.Trim().Replace('/', '\\').TrimEnd('\\'));
            }
            else
            {
                parts.Add(part);
            }
        }

        string joined = string.Join('\\', parts);
        try
        {
            return Path.GetFullPath(Path.IsPathFullyQualified(joined) ? joined : Path.Join(beside, joined)).TrimEnd('\\');
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return null;
        }
    }

    /// <summary>FileZilla's files of saved and recent sites in a settings folder; a folder already read is not read again.</summary>
    private static void FileZillaFolder(IFileProbe files, string folder, SecretFindings found, HashSet<string> read)
    {
        if (!read.Add(folder.TrimEnd('\\')))
        {
            return;
        }

        foreach (string name in new[] { "sitemanager.xml", "recentservers.xml" })
        {
            if (found.LoadXml(files, $@"{folder}\{name}") is { Root: { } root } file)
            {
                FileZillaServers(file, root, found);
            }
        }
    }

    private static void FileZillaServers(XmlFile file, MarkupElement root, SecretFindings found)
    {
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
