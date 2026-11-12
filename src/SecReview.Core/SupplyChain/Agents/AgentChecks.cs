using System.Text.Json;
using SecReview.Checks;
using SecReview.Config;
using SecReview.Probing;

namespace SecReview.SupplyChain.Agents;

/// <summary>
/// MCP servers give an AI tool new abilities by running a program with all the user's
/// rights. A server started through a package runner without a fixed version
/// (<c>npx -y some-server</c>, <c>uvx some-server</c>, a container image by tag) fetches
/// whatever is newest each time, so whoever takes over the package runs code here at the
/// next start. Also reported: a server reached over plain HTTP on another machine, and a
/// secret written into the settings file. Every AI tool's own settings file is read.
/// </summary>
public sealed class McpServersCheck : ICheck
{
    public const string Id = "sc.mcp.servers";

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.Medium, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (McpLocator.Locate(context.Probes, out IReadOnlyList<McpServer> servers, out bool anyFile, out string? unreadable) is { } failed)
        {
            return failed;
        }

        if (!anyFile)
        {
            return CheckOutcome.NotApplicable("No AI tool with MCP servers is set up for this user.");
        }

        var problems = new List<Finding>();
        foreach (McpServer server in servers)
        {
            string item = $"{server.Client}: server \"{server.Name}\"";
            if (server.UnpinnedPackage() is not null)
            {
                problems.Add(Finding.Problem(item, "Runs a package without a fixed version", "A fixed version", server.Source));
            }

            if (server.Address is { } address && IsPlainHttpElsewhere(address))
            {
                problems.Add(Finding.Problem(item, "Reached over plain HTTP", "HTTPS", server.Source));
            }

            if (server.LiteralSecrets > 0)
            {
                problems.Add(Finding.Problem(item, "A secret is written into the settings file", "Not stored as plain text", server.Source));
            }
        }

        if (problems.Count > 0)
        {
            // The same server set up in several projects of one tool reads the same; it is shown once.
            problems = [.. problems.DistinctBy(p => (p.Item, p.Found, p.Source))];
            int affected = problems.Select(p => p.Item).Distinct().Count();
            return CheckOutcome.Fail(
                affected == 1
                    ? "1 MCP server runs unpinned code, uses plain HTTP or keeps a secret in the open."
                    : $"{affected} MCP servers run unpinned code, use plain HTTP or keep a secret in the open.",
                problems);
        }

        if (unreadable is not null)
        {
            return CheckOutcome.Error(unreadable);
        }

        return CheckOutcome.Pass(
            servers.Count switch
            {
                0 => "No MCP servers are set up.",
                1 => "The MCP server that is set up runs no unpinned code and keeps no secret in the open.",
                _ => $"None of the {servers.Count} MCP servers runs unpinned code or keeps a secret in the open.",
            },
            Finding.Ok("MCP servers", servers.Count == 0 ? "None" : $"{servers.Count}, none unpinned", "No unpinned code"));
    }

    /// <summary>Plain HTTP to another machine; a server on this PC needs no encryption.</summary>
    private static bool IsPlainHttpElsewhere(string address) =>
        Uri.TryCreate(address.Trim(), UriKind.Absolute, out Uri? uri) && uri.Scheme == Uri.UriSchemeHttp && !uri.IsLoopback;
}

/// <summary>
/// AI coding tools ask before they run a command or change a file. Settings that switch the
/// asking off for good hand everything the user can do to whatever text the tool reads next:
/// Claude Code's bypass mode and automatic start of every project's MCP servers, Codex with
/// no approvals and no sandbox, Gemini CLI servers marked as trusted. (VS Code's own chat
/// approvals are in the editor check.)
/// </summary>
public sealed class AgentPermissionsCheck : ICheck
{
    public const string Id = "sc.agents.permissions";

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.High, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        SystemProbes probes = context.Probes;

        ProbeResult<string> profile = probes.Environment.Folder(KnownFolder.UserProfile);
        if (!profile.IsOk)
        {
            return CheckOutcome.Error("Windows did not say where your user folder is.");
        }

        var problems = new List<Finding>();
        var tools = new List<string>();
        string? unreadable = null;

        // Claude Code: the user's settings file (CLAUDE_CONFIG_DIR moves the folder).
        if (PersistentEnvironment.Read(probes, "CLAUDE_CONFIG_DIR", out string? claudeFolder, out _) is { } failed)
        {
            return failed;
        }

        string claudePath = $@"{claudeFolder?.TrimEnd('\\', '/') ?? profile.Value + @"\.claude"}\settings.json";
        JsonElement? claude = SettingsFiles.LoadJsonSettings(probes.Files, claudePath, out string? claudeProblem);
        unreadable ??= claudeProblem;
        if (claude is { ValueKind: JsonValueKind.Object } settings)
        {
            tools.Add("Claude Code");
            if (settings.TryGetProperty("permissions", out JsonElement permissions) && permissions.ValueKind == JsonValueKind.Object &&
                permissions.TryGetProperty("defaultMode", out JsonElement mode) && mode.ValueKind == JsonValueKind.String &&
                string.Equals(mode.GetString(), "bypassPermissions", StringComparison.OrdinalIgnoreCase))
            {
                problems.Add(Finding.Problem("Claude Code: asking before it acts", "Off for every session", "On", $"{claudePath} (permissions.defaultMode)"));
            }

            if (IsTrue(settings, "skipDangerousModePermissionPrompt"))
            {
                problems.Add(Finding.Problem(
                    "Claude Code: warning before the no-asking mode", "Switched off", "On", $"{claudePath} (skipDangerousModePermissionPrompt)"));
            }

            if (IsTrue(settings, "enableAllProjectMcpServers"))
            {
                problems.Add(Finding.Problem(
                    "Claude Code: MCP servers that a project brings", "Started without asking", "Ask first", $"{claudePath} (enableAllProjectMcpServers)"));
            }
        }

        // Codex: no approvals together with no sandbox.
        if (PersistentEnvironment.Read(probes, "CODEX_HOME", out string? codexHome, out _) is { } failedToo)
        {
            return failedToo;
        }

        string codexPath = $@"{codexHome?.TrimEnd('\\', '/') ?? profile.Value + @"\.codex"}\config.toml";
        if (SettingsFiles.Load(probes.Files, codexPath, SettingsFormat.Toml) is { } codex)
        {
            unreadable ??= codex.Problem;
            if (codex.Root is { } root)
            {
                tools.Add("Codex");
                // The profile named by "profile" replaces the top-level values with its own.
                ConfigMap? active = root["profile"] is ConfigScalar { Text.Length: > 0 } named
                    ? (root["profiles"] as ConfigMap)?[named.Text] as ConfigMap
                    : null;
                ConfigNode? approval = active?["approval_policy"] ?? root["approval_policy"];
                ConfigNode? sandbox = active?["sandbox_mode"] ?? root["sandbox_mode"];
                if (approval is ConfigScalar { Text: "never" } never && sandbox is ConfigScalar { Text: "danger-full-access" })
                {
                    problems.Add(Finding.Problem("Codex: asking before it acts", "Off, with no sandbox", "On, or sandboxed", codex.At(never)));
                }
            }
        }

        // Gemini CLI: a server marked "trust" has its tool calls run without confirmation.
        string geminiPath = $@"{profile.Value}\.gemini\settings.json";
        JsonElement? gemini = SettingsFiles.LoadJsonSettings(probes.Files, geminiPath, out string? geminiProblem);
        unreadable ??= geminiProblem;
        if (gemini is { ValueKind: JsonValueKind.Object } geminiSettings)
        {
            tools.Add("Gemini CLI");
            if (geminiSettings.TryGetProperty("mcpServers", out JsonElement servers) && servers.ValueKind == JsonValueKind.Object)
            {
                foreach (JsonProperty server in servers.EnumerateObject())
                {
                    if (server.Value.ValueKind == JsonValueKind.Object && IsTrue(server.Value, "trust"))
                    {
                        problems.Add(Finding.Problem(
                            $"Gemini CLI: server \"{server.Name}\"", "Trusted: its actions are not confirmed", "Ask first", $"{geminiPath} (mcpServers)"));
                    }
                }
            }
        }

        if (problems.Count > 0)
        {
            return CheckOutcome.Fail(
                problems.Count == 1
                    ? $"{problems[0].Item}: {Wording.LowerFirst(problems[0].Found)}."
                    : $"{problems.Count} settings let AI tools act without asking.",
                problems);
        }

        if (unreadable is not null)
        {
            return CheckOutcome.Error(unreadable);
        }

        return tools.Count == 0
            ? CheckOutcome.NotApplicable("No AI coding tool with such settings is set up for this user.")
            : CheckOutcome.Pass(
                $"{Wording.JoinWithAnd(tools)} {(tools.Count == 1 ? "asks" : "ask")} before acting.",
                Finding.Ok("Settings that skip asking", "None", "None"));
    }

    private static bool IsTrue(JsonElement element, string name) =>
        element.TryGetProperty(name, out JsonElement value) && value.ValueKind == JsonValueKind.True;
}
