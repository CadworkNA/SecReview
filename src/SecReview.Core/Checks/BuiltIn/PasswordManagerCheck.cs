using SecReview.Catalogue;
using SecReview.Probing;

namespace SecReview.Checks.BuiltIn;

/// <summary>
/// A password manager should be installed: as a desktop app, or as an extension in any profile
/// of Chrome, Edge, Brave, Vivaldi, Chromium or Firefox. Only the products on the shipped list
/// are recognised, so "none found" is worded as exactly that. The password stores built into
/// browsers are not counted.
/// </summary>
public sealed class PasswordManagerCheck : ICheck
{
    public const string Id = "password.manager";

    internal const string UninstallKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    internal const string UninstallKey32 = @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";

    private const string What = "the installed programs";

    /// <summary>Chromium browsers: name and the folder under <c>%LOCALAPPDATA%</c> that holds their profiles.</summary>
    private static readonly (string Name, string UserData)[] ChromiumBrowsers =
    [
        ("Chrome", @"Google\Chrome\User Data"),
        ("Edge", @"Microsoft\Edge\User Data"),
        ("Brave", @"BraveSoftware\Brave-Browser\User Data"),
        ("Vivaldi", @"Vivaldi\User Data"),
        ("Chromium", @"Chromium\User Data"),
    ];

    private readonly PasswordManagers _known;

    public PasswordManagerCheck()
        : this(PasswordManagers.Current)
    {
    }

    internal PasswordManagerCheck(PasswordManagers known) => _known = known;

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.Access, Severity.Low, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        SystemProbes probes = context.Probes;

        // Product name -> where it was found, in the order found.
        var found = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        string? problem = null;

        if (InstalledPrograms(probes.Registry, out List<string> programs, ref problem) is { } failed)
        {
            return failed;
        }

        foreach (PasswordManager manager in _known.Managers)
        {
            if (programs.Any(p => manager.Apps.Any(a => p.StartsWith(a, StringComparison.OrdinalIgnoreCase))))
            {
                Add(manager.Name, "Desktop app");
            }
        }

        ProbeResult<string> local = probes.Environment.Folder(KnownFolder.LocalAppData);
        ProbeResult<string> roaming = probes.Environment.Folder(KnownFolder.RoamingAppData);
        if (!local.IsOk || !roaming.IsOk)
        {
            problem ??= "Windows did not say where your browser profiles are.";
        }
        else
        {
            foreach ((string browser, string userData) in ChromiumBrowsers)
            {
                foreach (string id in ChromiumExtensions(probes.Files, $@"{local.Value}\{userData}", ref problem))
                {
                    Match(m => m.Chromium, id, $"Extension in {browser}");
                }
            }

            foreach (string id in FirefoxExtensions(probes.Files, $@"{roaming.Value}\Mozilla\Firefox\Profiles", ref problem))
            {
                Match(m => m.Firefox, id, "Extension in Firefox");
            }
        }

        if (found.Count > 0)
        {
            List<Finding> findings = [.. found.Select(f => Finding.Ok(f.Key, Wording.JoinWithAnd(f.Value), "Installed"))];
            return CheckOutcome.Pass(
                found.Count == 1
                    ? $"{found.Keys.First()} is installed."
                    : $"{Wording.JoinWithAnd([.. found.Keys])} are installed.",
                findings);
        }

        // Part of the search failed, so "none" is not known.
        if (problem is not null)
        {
            return CheckOutcome.Error(problem);
        }

        return CheckOutcome.Fail(
            "No password manager that SecReview knows was found.",
            Finding.Problem("Password manager", "None found", "Installed"),
            Finding.Note("Looked for", Wording.JoinWithAnd([.. _known.Managers.Select(m => m.Name)])));

        void Add(string name, string where)
        {
            if (!found.TryGetValue(name, out List<string>? places))
            {
                found[name] = places = [];
            }

            if (!places.Contains(where))
            {
                places.Add(where);
            }
        }

        void Match(Func<PasswordManager, IReadOnlyList<string>> identifiers, string id, string where)
        {
            foreach (PasswordManager manager in _known.Managers)
            {
                if (identifiers(manager).Contains(id, StringComparer.OrdinalIgnoreCase))
                {
                    Add(manager.Name, where);
                }
            }
        }
    }

    /// <summary>The display names of installed desktop programs, for all users and for this one.</summary>
    private static CheckOutcome? InstalledPrograms(IRegistryProbe registry, out List<string> names, ref string? problem)
    {
        names = [];
        (RegistryRoot Root, string Key)[] places =
        [
            (RegistryRoot.LocalMachine, UninstallKey),
            (RegistryRoot.LocalMachine, UninstallKey32),
            (RegistryRoot.CurrentUser, UninstallKey),
        ];

        foreach ((RegistryRoot root, string key) in places)
        {
            ProbeResult<IReadOnlyList<string>> programs = registry.GetSubKeyNames(root, key);
            if (programs.Status == ProbeStatus.NotFound)
            {
                continue;
            }

            if (!programs.IsOk)
            {
                return ProbeOutcomes.FromFailure(programs, What);
            }

            foreach (string program in programs.Value!)
            {
                // One entry that cannot be read does not stop the search, but "none found" is
                // then no longer certain.
                if (RegistryReader.Text(registry, root, $@"{key}\{program}", "DisplayName", What, out string? name) is not null)
                {
                    problem ??= "Part of the list of installed programs could not be read.";
                }
                else if (name is not null)
                {
                    names.Add(name);
                }
            }
        }

        return null;
    }

    /// <summary>The extension identifiers installed in any profile of one Chromium browser.</summary>
    private static List<string> ChromiumExtensions(IFileProbe files, string userData, ref string? problem)
    {
        var identifiers = new List<string>();
        ProbeResult<IReadOnlyList<FileEntry>> profiles = files.List(userData);
        if (profiles.Status == ProbeStatus.NotFound)
        {
            return identifiers;
        }

        if (!profiles.IsOk)
        {
            problem ??= "A browser's profile folder could not be read.";
            return identifiers;
        }

        foreach (FileEntry profile in profiles.Value!)
        {
            if (!profile.IsDirectory || profile.IsLink)
            {
                continue;
            }

            ProbeResult<IReadOnlyList<FileEntry>> extensions = files.List($@"{userData}\{profile.Name}\Extensions");
            if (extensions.IsOk)
            {
                identifiers.AddRange(extensions.Value!.Where(e => e.IsDirectory).Select(e => e.Name));
            }
            else if (extensions.Status != ProbeStatus.NotFound)
            {
                problem ??= "A browser's extensions folder could not be read.";
            }
        }

        return identifiers;
    }

    /// <summary>The extension identifiers installed in any Firefox profile ("identifier.xpi" files).</summary>
    private static List<string> FirefoxExtensions(IFileProbe files, string profilesFolder, ref string? problem)
    {
        var identifiers = new List<string>();
        ProbeResult<IReadOnlyList<FileEntry>> profiles = files.List(profilesFolder);
        if (profiles.Status == ProbeStatus.NotFound)
        {
            return identifiers;
        }

        if (!profiles.IsOk)
        {
            problem ??= "The Firefox profile folder could not be read.";
            return identifiers;
        }

        foreach (FileEntry profile in profiles.Value!)
        {
            if (!profile.IsDirectory || profile.IsLink)
            {
                continue;
            }

            ProbeResult<IReadOnlyList<FileEntry>> extensions = files.List($@"{profilesFolder}\{profile.Name}\extensions");
            if (extensions.IsOk)
            {
                identifiers.AddRange(extensions.Value!
                    .Where(e => !e.IsDirectory && e.Name.EndsWith(".xpi", StringComparison.OrdinalIgnoreCase))
                    .Select(e => e.Name[..^4]));
            }
            else if (extensions.Status != ProbeStatus.NotFound)
            {
                problem ??= "A Firefox extensions folder could not be read.";
            }
        }

        return identifiers;
    }
}
