using System.Text.Json;
using SecReview.Checks;
using SecReview.Config;
using SecReview.Probing;
using SecReview.SupplyChain.Variables;

namespace SecReview.SupplyChain.Agents;

/// <summary>One MCP server as an AI tool's settings define it. Values of its variables and headers are not kept.</summary>
/// <param name="Client">The AI tool whose settings it is in ("Claude Code", "VS Code").</param>
/// <param name="Name">The server's name in those settings.</param>
/// <param name="Command">The program it starts; null for a server reached by address.</param>
/// <param name="Arguments">The program's arguments.</param>
/// <param name="Address">The address of a remote server; null for a local program.</param>
/// <param name="LiteralSecrets">How many variables or headers hold a secret written out in the file.</param>
/// <param name="Source">Where it is defined, for a finding.</param>
internal sealed record McpServer(
    string Client, string Name, string? Command, IReadOnlyList<string> Arguments, string? Address, int LiteralSecrets, string Source)
{
    /// <summary>
    /// The package this server is fetched and run from when no fixed version is given, as
    /// written ("@scope/name", "name@latest"); null when the server is not run through a
    /// package runner, or names an exact version.
    /// </summary>
    public string? UnpinnedPackage()
    {
        if (Command is null)
        {
            return null;
        }

        // "cmd /c npx …" and the like: the runner is what follows.
        var words = new List<string> { Command };
        words.AddRange(Arguments);
        string first = Program(words[0]);
        if (first == "cmd")
        {
            // Any of cmd's own switches may come before "/c" ("cmd /d /s /c npx …").
            int run = words.FindIndex(1, w => w.Equals("/c", StringComparison.OrdinalIgnoreCase) || w.Equals("/k", StringComparison.OrdinalIgnoreCase));
            if (run > 0)
            {
                words.RemoveRange(0, run + 1);
            }
        }
        else if (first is "powershell" or "pwsh")
        {
            int run = words.FindIndex(1, w => w.StartsWith("-c", StringComparison.OrdinalIgnoreCase));
            if (run > 0 && run + 1 < words.Count)
            {
                words = [.. words[run + 1].Split(' ', StringSplitOptions.RemoveEmptyEntries), .. words.Skip(run + 2)];
            }
        }

        if (words.Count == 0)
        {
            return null;
        }

        string runner = Program(words[0]);
        List<string> rest = words.GetRange(1, words.Count - 1);

        switch (runner)
        {
            case "npx" or "bunx" or "pnpx" or "pnx":
                return Unpinned(NodePackage(rest));
            case "npm" or "pnpm" or "yarn" or "bun" when rest.Count > 0 && rest[0] is "dlx" or "x" or "exec":
                return Unpinned(NodePackage(rest.GetRange(1, rest.Count - 1)));
            case "uvx":
                return UnpinnedPython(rest);
            case "uv" when rest.Count > 1 && rest[0] == "tool" && rest[1] == "run":
                return UnpinnedPython(rest.GetRange(2, rest.Count - 2));
            case "pipx" when rest.Count > 0 && rest[0] == "run":
                return UnpinnedPython(rest.GetRange(1, rest.Count - 1));
            case "docker" or "podman" when rest.Contains("run"):
                // Only an image named by its digest is fixed; a tag can be moved.
                return ContainerImage(rest.GetRange(rest.IndexOf("run") + 1, rest.Count - rest.IndexOf("run") - 1)) is { } image &&
                    image.Contains("@sha256:", StringComparison.Ordinal)
                        ? null
                        : "a container image named by tag";
            default:
                return null;
        }
    }

    /// <summary>Options of "docker run" that take a value as the next word, so that the value is not taken for the image.</summary>
    private static readonly string[] ContainerValueOptions =
    [
        "-e", "--env", "--env-file", "-v", "--volume", "--mount", "-p", "--publish", "--name", "--network", "--net", "-w", "--workdir",
        "-u", "--user", "--entrypoint", "-l", "--label", "-h", "--hostname", "--add-host", "-m", "--memory", "--cpus", "--platform", "--pull",
    ];

    /// <summary>The image a "docker run" names: the first word that is neither an option nor an option's value.</summary>
    private static string? ContainerImage(List<string> arguments)
    {
        for (int i = 0; i < arguments.Count; i++)
        {
            string argument = arguments[i];
            if (!argument.StartsWith('-'))
            {
                return argument;
            }

            if (!argument.Contains('=', StringComparison.Ordinal) && ContainerValueOptions.Contains(argument, StringComparer.Ordinal))
            {
                i++;
            }
        }

        return null;
    }

    /// <summary>Options of npx and its like that take a value as the next word.</summary>
    private static readonly string[] NodeValueOptions =
        ["--registry", "--cache", "--userconfig", "--prefix", "-w", "--workspace", "--node-options", "--loglevel"];

    /// <summary>The program's name without folder or extension, in lower case.</summary>
    private static string Program(string command)
    {
        string name = command.Trim().Trim('"');
        name = name[(name.LastIndexOfAny(['\\', '/']) + 1)..].ToLowerInvariant();
        foreach (string extension in (string[])[".exe", ".cmd", ".bat", ".ps1"])
        {
            if (name.EndsWith(extension, StringComparison.Ordinal))
            {
                return name[..^extension.Length];
            }
        }

        return name;
    }

    /// <summary>The package an npx-style runner is asked for: "--package x" if given, else the first word that is not an option.</summary>
    private static string? NodePackage(List<string> arguments)
    {
        for (int i = 0; i < arguments.Count; i++)
        {
            string argument = arguments[i];
            if (argument is "-p" or "--package" && i + 1 < arguments.Count)
            {
                return arguments[i + 1];
            }

            if (argument.StartsWith("--package=", StringComparison.Ordinal))
            {
                return argument["--package=".Length..];
            }

            if (argument == "--")
            {
                continue;
            }

            if (!argument.StartsWith('-'))
            {
                return argument;
            }

            // "--registry https://…": the next word is the option's value, not the package.
            if (NodeValueOptions.Contains(argument, StringComparer.Ordinal))
            {
                i++;
            }
        }

        return null;
    }

    /// <summary>
    /// The package if its version is not an exact one ("name", "name@latest", "name@^1",
    /// "name@1"); null if it is ("name@1.2.3"). "1" and "1.2" are ranges to npm, so only a full
    /// three-part version counts.
    /// </summary>
    private static string? Unpinned(string? package)
    {
        if (string.IsNullOrWhiteSpace(package) || package.StartsWith('.') || package.Contains('\\', StringComparison.Ordinal) ||
            package.Contains(":/", StringComparison.Ordinal))
        {
            // No package, or a local path or address: not something a registry can change under you.
            return null;
        }

        int at = package.LastIndexOf('@');
        string version = at > 0 ? package[(at + 1)..] : string.Empty;
        string[] parts = version.Split(['-', '+'], 2)[0].Split('.');
        bool exact = parts.Length == 3 && parts.All(p => p.Length > 0 && p.All(char.IsAsciiDigit)) &&
            version.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '+');
        return exact ? null : package;
    }

    private static string? UnpinnedPython(List<string> arguments)
    {
        string? package = null;
        for (int i = 0; i < arguments.Count; i++)
        {
            string argument = arguments[i];
            if (argument is "--from" or "--spec" or "--with" && i + 1 < arguments.Count)
            {
                if (argument != "--with")
                {
                    package = arguments[i + 1];
                }

                i++;
            }
            else if (argument.StartsWith("--from=", StringComparison.Ordinal) || argument.StartsWith("--spec=", StringComparison.Ordinal))
            {
                package = argument[(argument.IndexOf('=', StringComparison.Ordinal) + 1)..];
            }
            else if (!argument.StartsWith('-'))
            {
                package ??= argument;
                break;
            }
        }

        if (package is null)
        {
            return null;
        }

        // "name==1.2.3" is exact; uvx also takes "name@1.2.3".
        int equals = package.IndexOf("==", StringComparison.Ordinal);
        if (equals > 0 && package.Length > equals + 2 && char.IsAsciiDigit(package[equals + 2]) && !package.Contains('*', StringComparison.Ordinal))
        {
            return null;
        }

        return Unpinned(package);
    }
}

/// <summary>
/// Reads the MCP servers that AI coding tools are set up with, from each tool's own settings
/// file. No tool and no server is started. Project-level files (<c>.mcp.json</c>,
/// <c>.vscode\mcp.json</c>) can add more; these are the ones every session of the tool gets.
/// </summary>
internal static class McpLocator
{
    /// <summary>Claude Code's state file holds every project's history and can be large.</summary>
    private const int LargeFile = 16 * 1024 * 1024;

    /// <summary>
    /// The servers of every tool found. <paramref name="anyFile"/> says whether any settings
    /// file exists; <paramref name="problem"/> is the first file that could not be used.
    /// </summary>
    public static CheckOutcome? Locate(SystemProbes probes, out IReadOnlyList<McpServer> servers, out bool anyFile, out string? problem)
    {
        var found = new List<McpServer>();
        (servers, anyFile, problem) = (found, false, null);
        IFileProbe files = probes.Files;

        ProbeResult<string> profile = probes.Environment.Folder(KnownFolder.UserProfile);
        ProbeResult<string> roaming = probes.Environment.Folder(KnownFolder.RoamingAppData);
        if (!profile.IsOk || !roaming.IsOk)
        {
            return CheckOutcome.Error("Windows did not say where your user folders are.");
        }

        string home = profile.Value!;
        string data = roaming.Value!;

        // Claude Code keeps its state file in the folder CLAUDE_CONFIG_DIR names, when that is set.
        if (PersistentEnvironment.Read(probes, "CLAUDE_CONFIG_DIR", out string? claudeFolder, out _) is { } unreadClaude)
        {
            return unreadClaude;
        }

        string claudeState = string.IsNullOrWhiteSpace(claudeFolder)
            ? $@"{home}\.claude.json"
            : $@"{claudeFolder.Trim().Replace('/', '\\').TrimEnd('\\')}\.claude.json";

        // JSON files: the tool, the file, and the property the servers are under.
        (string Client, string Path, string Property, int MaximumBytes)[] jsonFiles =
        [
            ("Claude Desktop", $@"{data}\Claude\claude_desktop_config.json", "mcpServers", IFileProbe.DefaultMaximumBytes),
            ("Claude Code", claudeState, "mcpServers", LargeFile),
            ("VS Code", $@"{data}\Code\User\mcp.json", "servers", IFileProbe.DefaultMaximumBytes),
            ("VS Code Insiders", $@"{data}\Code - Insiders\User\mcp.json", "servers", IFileProbe.DefaultMaximumBytes),
            ("Cursor", $@"{home}\.cursor\mcp.json", "mcpServers", IFileProbe.DefaultMaximumBytes),
            ("Windsurf", $@"{home}\.codeium\windsurf\mcp_config.json", "mcpServers", IFileProbe.DefaultMaximumBytes),
            ("GitHub Copilot CLI", $@"{home}\.copilot\mcp-config.json", "mcpServers", IFileProbe.DefaultMaximumBytes),
            ("Gemini CLI", $@"{home}\.gemini\settings.json", "mcpServers", IFileProbe.DefaultMaximumBytes),
            ("Cline", $@"{data}\Code\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json", "mcpServers", IFileProbe.DefaultMaximumBytes),
            ("Roo Code", $@"{data}\Code\User\globalStorage\rooveterinaryinc.roo-cline\settings\mcp_settings.json", "mcpServers", IFileProbe.DefaultMaximumBytes),
        ];

        foreach ((string client, string path, string property, int maximum) in jsonFiles)
        {
            JsonElement? json = SettingsFiles.LoadJsonSettings(files, path, out string? unusable, maximum);
            if (unusable is not null)
            {
                anyFile = true;
                problem ??= unusable;
                continue;
            }

            if (json is not { ValueKind: JsonValueKind.Object } root)
            {
                continue;
            }

            anyFile = true;
            AddJson(found, client, path, root, property);

            // Claude Code also keeps servers per project folder in the same file.
            if (client == "Claude Code" && root.TryGetProperty("projects", out JsonElement projects) && projects.ValueKind == JsonValueKind.Object)
            {
                foreach (JsonProperty project in projects.EnumerateObject())
                {
                    if (project.Value.ValueKind == JsonValueKind.Object)
                    {
                        AddJson(found, "Claude Code (one project)", path, project.Value, property);
                    }
                }
            }
        }

        // Codex: [mcp_servers.<name>] tables in a TOML file.
        if (PersistentEnvironment.Read(probes, "CODEX_HOME", out string? codexHome, out _) is { } failed)
        {
            return failed;
        }

        string codexPath = $@"{codexHome?.TrimEnd('\\', '/') ?? home + @"\.codex"}\config.toml";
        if (SettingsFiles.Load(files, codexPath, SettingsFormat.Toml) is { } codex)
        {
            anyFile = true;
            if (codex.Root is null)
            {
                problem ??= codex.Problem;
            }
            else if (codex.Root["mcp_servers"] is ConfigMap tables)
            {
                foreach ((string name, ConfigNode node) in tables.Entries)
                {
                    if (node is not ConfigMap server)
                    {
                        continue;
                    }

                    string[] arguments = server["args"] is ConfigList list ? [.. list.Items.OfType<ConfigScalar>().Select(a => a.Text)] : [];
                    int secrets = (server["env"] as ConfigMap)?.Entries.Count(e => IsSecret(e.Key, (e.Value as ConfigScalar)?.Text)) ?? 0;
                    found.Add(new McpServer(
                        "Codex", name, (server["command"] as ConfigScalar)?.Text, arguments, (server["url"] as ConfigScalar)?.Text, secrets, codex.At(server)));
                }
            }
        }

        return null;
    }

    private static void AddJson(List<McpServer> found, string client, string path, JsonElement root, string property)
    {
        if (!root.TryGetProperty(property, out JsonElement servers) || servers.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        foreach (JsonProperty entry in servers.EnumerateObject())
        {
            if (entry.Value.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            JsonElement server = entry.Value;
            string[] arguments = server.TryGetProperty("args", out JsonElement args) && args.ValueKind == JsonValueKind.Array
                ? [.. args.EnumerateArray().Where(a => a.ValueKind == JsonValueKind.String).Select(a => a.GetString()!)]
                : [];

            int secrets = 0;
            foreach (string group in (string[])["env", "headers"])
            {
                if (server.TryGetProperty(group, out JsonElement values) && values.ValueKind == JsonValueKind.Object)
                {
                    secrets += values.EnumerateObject().Count(v => IsSecret(v.Name, v.Value.ValueKind == JsonValueKind.String ? v.Value.GetString() : null));
                }
            }

            found.Add(new McpServer(
                client, entry.Name, Text(server, "command"), arguments, Text(server, "url") ?? Text(server, "httpUrl") ?? Text(server, "serverUrl"), secrets, $"{path} ({property})"));
        }
    }

    private static string? Text(JsonElement element, string name) =>
        element.TryGetProperty(name, out JsonElement value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    /// <summary>
    /// Whether a variable or header holds a secret written out in the file: its name says
    /// "secret" (or it is the Authorization header) and its value is not a reference to a
    /// variable or an input the tool asks for ("${env:NAME}", "${input:name}").
    /// </summary>
    private static bool IsSecret(string name, string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Contains("${", StringComparison.Ordinal))
        {
            return false;
        }

        return EnvironmentTokensCheck.NamesASecret(name) || name.Equals("Authorization", StringComparison.OrdinalIgnoreCase) ||
            name.EndsWith("-Key", StringComparison.OrdinalIgnoreCase) || name.EndsWith("-Token", StringComparison.OrdinalIgnoreCase);
    }
}
