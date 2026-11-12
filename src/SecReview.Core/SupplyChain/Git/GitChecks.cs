using System.Globalization;
using SecReview.Checks;
using SecReview.Probing;

namespace SecReview.SupplyChain.Git;

/// <summary>
/// Git's settings for the user and the PC must not switch off what protects a clone or fetch:
/// TLS certificate checks, the ownership check on repositories, the limits on which
/// transports a repository may ask for, and they must not rewrite secure addresses to
/// unencrypted ones. Settings that make Git run a program (a hooks folder for every
/// repository, another SSH program, a file watcher) are listed, not failed. Included files
/// are followed; ones included only for some repositories are marked as such.
/// </summary>
public sealed class GitSettingsCheck : ICheck
{
    public const string Id = "sc.git.settings";

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.High, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (GitLocator.Locate(context.Probes, out GitInstall? git) is { } failed)
        {
            return failed;
        }

        if (git is null)
        {
            return CheckOutcome.NotApplicable("Git is not installed.");
        }

        var problems = new List<Finding>();

        // TLS: for every address, and for single ones ([http "https://host/"]).
        foreach (GitEntry tls in git.Deciding("http", "sslverify").Where(e => e.Setting.AsBoolean == false))
        {
            problems.Add(Finding.Problem("TLS certificate checks" + tls.Scope, "Off", "On", tls.Source));
        }

        foreach (GitEntry entry in git.DecidingPerSubsection("http", "sslverify"))
        {
            if (entry.Setting.AsBoolean == false)
            {
                problems.Add(Finding.Problem($"TLS certificate checks for {Host(entry.Setting.Subsection!)}{entry.Scope}", "Off", "On", entry.Source));
            }
        }

        // The ownership check: "*" switches it off everywhere. An empty value clears the list so
        // far; one in a file included for some repositories only does not clear it for the rest.
        GitEntry? everywhere = null;
        foreach (GitEntry entry in git.All("safe", "directory").Where(e => !e.Conditional))
        {
            everywhere = entry.Setting.Value switch
            {
                null or "" => null,
                "*" => entry,
                _ => everywhere,
            };
        }

        IEnumerable<GitEntry> switchedOff = git.All("safe", "directory").Where(e => e.Conditional && e.Setting.Value == "*");
        foreach (GitEntry entry in everywhere is null ? switchedOff : switchedOff.Prepend(everywhere))
        {
            problems.Add(Finding.Problem("Ownership check on repositories" + entry.Scope, "Off for every folder", "On", entry.Source));
        }

        // Transports: "always" lets a repository (a submodule address, say) pick one.
        foreach (GitEntry transports in git.Deciding("protocol", "allow").Where(IsAlways))
        {
            problems.Add(Finding.Problem("Transports a repository may ask for" + transports.Scope, "All of them", "Git's own limits", transports.Source));
        }

        foreach (GitEntry entry in git.DecidingPerSubsection("protocol", "allow"))
        {
            if (!IsAlways(entry))
            {
                continue;
            }

            switch (entry.Setting.Subsection!.ToLowerInvariant())
            {
                case "ext":
                    problems.Add(Finding.Problem("The \"ext\" transport" + entry.Scope, "Always allowed: an address can run a command", "Not allowed", entry.Source));
                    break;
                case "file":
                    problems.Add(Finding.Problem("Local-folder transport" + entry.Scope, "Always allowed, for submodules too", "Git's own limit", entry.Source));
                    break;
            }
        }

        // [url "http://host/"] insteadOf = https://host/ sends what should be encrypted in the clear.
        foreach (GitEntry entry in git.Entries.Where(e => e.Setting is { Section: "url", Subsection: not null, Name: "insteadof" or "pushinsteadof" }))
        {
            if (IsUnencrypted(entry.Setting.Subsection!) && entry.Setting.Value is { } replaced && !IsUnencrypted(replaced))
            {
                problems.Add(Finding.Problem("Address rewrite" + entry.Scope, "Secure addresses are sent unencrypted", "No such rewrite", entry.Source));
            }
        }

        if (problems.Count > 0)
        {
            return CheckOutcome.Fail(
                problems.Count == 1
                    ? $"Git: {Wording.LowerFirst(problems[0].Item)}: {Wording.LowerFirst(problems[0].Found)}."
                    : $"Git has {problems.Count} settings that weaken its protections.",
                problems);
        }

        // Nothing found. If a settings file could not be read, "nothing wrong" is not known.
        if (git.Problem is { } problem)
        {
            return CheckOutcome.Error(problem);
        }

        var findings = new List<Finding>
        {
            Finding.Ok("TLS certificate checks", "On", "On"),
            Finding.Ok("Ownership check on repositories", "On", "On"),
        };

        // Settings that make Git run a program: a choice, listed so that it stays one.
        (string Name, string Item, string Found)[] programs =
        [
            ("hookspath", "Hooks folder for every repository (core.hooksPath)", "Set: its scripts run on Git commands"),
            ("sshcommand", "SSH program (core.sshCommand)", "Replaced by a program you chose"),
        ];
        foreach ((string name, string item, string found) in programs)
        {
            foreach (GitEntry program in git.Deciding("core", name).Where(e => e.Setting.Value is { Length: > 0 }))
            {
                findings.Add(Finding.Note(item + program.Scope, found, program.Source));
            }
        }

        // core.fsmonitor is yes/no for Git's own watcher, or the path of a program to run.
        foreach (GitEntry watcher in git.Deciding("core", "fsmonitor").Where(e => e.Setting is { Value.Length: > 0, AsBoolean: null }))
        {
            findings.Add(Finding.Note("File watcher (core.fsmonitor)" + watcher.Scope, "A program you chose", watcher.Source));
        }

        int notes = findings.Count(f => f.Status == FindingStatus.Note);
        return CheckOutcome.Pass(
            notes switch
            {
                0 => "Git's settings keep its protections on.",
                1 => "Git's protections are on; 1 setting makes Git run a program you chose.",
                _ => string.Create(CultureInfo.InvariantCulture, $"Git's protections are on; {notes} settings make Git run programs you chose."),
            },
            findings);
    }

    private static bool IsAlways(GitEntry entry) => string.Equals(entry.Setting.Value?.Trim(), "always", StringComparison.OrdinalIgnoreCase);

    private static bool IsUnencrypted(string address)
    {
        string text = address.TrimStart();
        return text.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || text.StartsWith("git://", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>The host of an address; never more, since an address may carry a user name.</summary>
    internal static string Host(string address) =>
        Uri.TryCreate(address.Trim(), UriKind.Absolute, out Uri? uri) && uri.Host.Length > 0 ? uri.Host : "one address";
}

/// <summary>
/// Git must not keep passwords and tokens in plain files: the "store" helper and its
/// <c>.git-credentials</c> file, Git Credential Manager told to use plain files, and a
/// <c>_netrc</c> file with passwords. Only the file and how many entries it holds are
/// reported, never an address, user name or password.
/// </summary>
public sealed class GitCredentialsCheck : ICheck
{
    public const string Id = "sc.git.credentials";

    private const string Expected = "Kept by Windows, not in a file";

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.High, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        SystemProbes probes = context.Probes;

        if (GitLocator.Locate(probes, out GitInstall? git) is { } failed)
        {
            return failed;
        }

        // Git's home: where its files of saved passwords are, whether or not Git itself was found.
        if (GitLocator.Home(probes, out string home) is { } noHome)
        {
            return noHome;
        }

        var problems = new List<Finding>();
        string? unreadable = git?.Problem;
        bool anyFile = false;

        // Files of saved passwords: Git's own, then the one curl and Git read for HTTP sign-in.
        string configHome = git?.ConfigHome ?? $@"{home}\.config";
        foreach (string path in (string[])[$@"{home}\.git-credentials", $@"{configHome}\git\credentials"])
        {
            ProbeResult<string> text = probes.Files.ReadText(path);
            if (text.Status == ProbeStatus.NotFound)
            {
                continue;
            }

            anyFile = true;
            if (!text.IsOk)
            {
                unreadable ??= $"{Name(path)} could not be read.";
                continue;
            }

            int entries = text.Value!.Split('\n').Count(line => line.Trim().Length > 0);
            if (entries > 0)
            {
                problems.Add(Finding.Problem(
                    $"Saved passwords ({Name(path)})", entries == 1 ? "1, as plain text" : $"{entries}, as plain text", "None", path));
            }
        }

        foreach (string path in (string[])[$@"{home}\_netrc", $@"{home}\.netrc"])
        {
            ProbeResult<string> text = probes.Files.ReadText(path);
            if (text.Status == ProbeStatus.NotFound)
            {
                continue;
            }

            anyFile = true;
            if (!text.IsOk)
            {
                unreadable ??= $"{Name(path)} could not be read.";
                continue;
            }

            int passwords = NetrcPasswords(text.Value!);
            if (passwords > 0)
            {
                problems.Add(Finding.Problem(
                    $"Saved passwords ({Name(path)})", passwords == 1 ? "1, as plain text" : $"{passwords}, as plain text", "None", path));
            }
        }

        if (git is null && !anyFile)
        {
            return CheckOutcome.NotApplicable("Git is not installed.");
        }

        if (git is not null)
        {
            // Helpers add up, per-address ones too; an empty value clears the whole list so far.
            // One in a file included for some repositories only does not clear it for the rest.
            var helpers = new List<GitEntry>();
            foreach (GitEntry entry in git.Entries.Where(e => e.Setting is { Section: "credential", Name: "helper" }))
            {
                if (!string.IsNullOrWhiteSpace(entry.Setting.Value))
                {
                    helpers.Add(entry);
                }
                else if (!entry.Conditional)
                {
                    helpers.Clear();
                }
            }

            foreach (GitEntry helper in helpers)
            {
                if (IsStoreHelper(helper.Setting.Value!))
                {
                    problems.Add(Finding.Problem("Password helper" + helper.Scope, "\"store\": saves passwords in a plain file", Expected, helper.Source));
                }
            }

            foreach (GitEntry store in git.Deciding("credential", "credentialstore"))
            {
                if (string.Equals(store.Setting.Value?.Trim(), "plaintext", StringComparison.OrdinalIgnoreCase))
                {
                    problems.Add(Finding.Problem("Git Credential Manager" + store.Scope, "Told to save passwords in plain files", Expected, store.Source));
                }
            }
        }

        if (PersistentEnvironment.Read(probes, "GCM_CREDENTIAL_STORE", out string? fromVariable, out string? variableSource) is { } unread)
        {
            return unread;
        }

        if (string.Equals(fromVariable?.Trim(), "plaintext", StringComparison.OrdinalIgnoreCase))
        {
            problems.Add(Finding.Problem("Git Credential Manager", "Told to save passwords in plain files", Expected, variableSource));
        }

        if (problems.Count > 0)
        {
            return CheckOutcome.Fail(
                problems.Count == 1
                    ? $"Git: {Wording.LowerFirst(problems[0].Item)}: {Wording.LowerFirst(problems[0].Found)}."
                    : $"Git keeps passwords as plain text in {problems.Count} ways.",
                problems);
        }

        return unreadable is not null
            ? CheckOutcome.Error(unreadable)
            : CheckOutcome.Pass("Git keeps no passwords in plain files.", Finding.Ok("Passwords in plain files", "None", "None"));
    }

    private static string Name(string path) => path[(path.LastIndexOf('\\') + 1)..];

    /// <summary>
    /// Whether a helper is Git's plain-file one, however it is written: "store", "store --file x",
    /// the program by its own name or full path, or "!git credential-store".
    /// </summary>
    internal static bool IsStoreHelper(string helper)
    {
        // The program's own name anywhere in the command covers a full path, with or without spaces.
        if (helper.Contains("credential-store", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        string[] words = helper.Trim().Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
        return words.Length > 0 && words[0].Equals("store", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>How many passwords a netrc file holds: each "password" word followed by a value.</summary>
    internal static int NetrcPasswords(string text)
    {
        string[] words = text.Split([' ', '\t', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
        int passwords = 0;
        for (int i = 0; i + 1 < words.Length; i++)
        {
            if (words[i] == "password")
            {
                passwords++;
                i++;
            }
        }

        return passwords;
    }
}
