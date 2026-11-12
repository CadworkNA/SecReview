using SecReview.Checks;
using SecReview.Probing;
using SecReview.SupplyChain;
using SecReview.SupplyChain.Agents;
using SecReview.Tests.Checks;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.SupplyChain;

[TestClass]
public sealed class AgentChecksTests
{
    private static readonly string Profile = FakeProbes.UserProfile;
    private static readonly string Roaming = FakeProbes.FolderPath(KnownFolder.RoamingAppData);

    private static readonly string ClaudeDesktop = Roaming + @"\Claude\claude_desktop_config.json";
    private static readonly string ClaudeState = Profile + @"\.claude.json";
    private static readonly string ClaudeSettings = Profile + @"\.claude\settings.json";
    private static readonly string VsCodeMcp = Roaming + @"\Code\User\mcp.json";
    private static readonly string CodexConfig = Profile + @"\.codex\config.toml";
    private static readonly string GeminiSettings = Profile + @"\.gemini\settings.json";

    private static readonly McpServersCheck Servers = new();
    private static readonly AgentPermissionsCheck Permissions = new();

    private static FakeProbes File(string path, string text) => new FakeProbes().WithFile(path, text);

    /// <summary>Claude Desktop with one server started by the given command and arguments.</summary>
    private static FakeProbes Desktop(string command, params string[] arguments) => File(
        ClaudeDesktop,
        $$"""{ "mcpServers": { "tool": { "command": "{{command}}", "args": [{{string.Join(", ", arguments.Select(a => $"\"{a}\""))}}] } } }""");

    private static string Everything(CheckOutcome outcome) =>
        outcome.Summary + string.Join('|', outcome.Findings.Select(f => f.Item + f.Found + f.Expected + f.Source));

    [TestMethod]
    public void WithoutAnyAiTool_NeitherCheckApplies_AndNeitherRunsElevated()
    {
        Assert.AreEqual(CheckStatus.NotApplicable, Servers.Run(new FakeProbes()).Status);
        Assert.AreEqual(CheckStatus.NotApplicable, Permissions.Run(new FakeProbes()).Status);
        Assert.AreEqual(CheckScope.User, Servers.Definition.Scope);
        Assert.AreEqual(CheckScope.User, Permissions.Definition.Scope);
    }

    // MCP servers

    [TestMethod]
    [DataRow("npx", new[] { "-y", "some-server" })]
    [DataRow("npx", new[] { "-y", "some-server@latest" })]
    [DataRow("npx", new[] { "@scope/some-server" })]
    [DataRow("npx", new[] { "-y", "some-server@^1.2.0" })]
    [DataRow("npx.cmd", new[] { "--package", "some-server", "run-it" })]
    [DataRow("cmd", new[] { "/c", "npx", "-y", "some-server" })]
    [DataRow("C:/Program Files/nodejs/npx.cmd", new[] { "some-server" })]
    [DataRow("pnpm", new[] { "dlx", "some-server" })]
    [DataRow("bunx", new[] { "some-server" })]
    [DataRow("uvx", new[] { "some-server" })]
    [DataRow("uvx", new[] { "--from", "some-server", "run-it" })]
    [DataRow("uv", new[] { "tool", "run", "some-server>=1.0" })]
    [DataRow("pipx", new[] { "run", "some-server" })]
    [DataRow("docker", new[] { "run", "-i", "--rm", "vendor/some-server:latest" })]
    public void Servers_RunFromAPackageWithoutAFixedVersion_Fail(string command, string[] arguments)
    {
        CheckOutcome outcome = Servers.Run(Desktop(command, arguments));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("1 MCP server runs unpinned code, uses plain HTTP or keeps a secret in the open.", outcome.Summary);
        Assert.AreEqual("Claude Desktop: server \"tool\": Runs a package without a fixed version (expected A fixed version) [problem]", outcome.Rows()[0]);
    }

    [TestMethod]
    [DataRow("npx", new[] { "-y", "some-server@1.2.3" })]
    [DataRow("npx", new[] { "@scope/some-server@2.0.0-beta.1" })]
    [DataRow("npx", new[] { "--package=some-server@1.2.3", "run-it" })]
    [DataRow("npx", new[] { "./local/server.js" })]
    [DataRow("uvx", new[] { "some-server==1.2.3" })]
    [DataRow("uvx", new[] { "--from", "some-server==1.2.3", "run-it" })]
    [DataRow("uvx", new[] { "some-server@1.2.3" })]
    [DataRow("pipx", new[] { "run", "--spec", "some-server==1.2.3", "run-it" })]
    [DataRow("docker", new[] { "run", "-i", "vendor/some-server@sha256:0123456789abcdef" })]
    [DataRow("node", new[] { "D:/tools/server/index.js" })]
    [DataRow("D:/tools/server.exe", new string[0])]
    public void Servers_WithAFixedVersion_OrALocalProgram_Pass(string command, string[] arguments)
    {
        Assert.AreEqual(CheckStatus.Pass, Servers.Run(Desktop(command, arguments)).Status);
    }

    [TestMethod]
    public void Servers_ASecretWrittenIntoTheFile_Fails_WithoutShowingIt_AndAReferenceDoesNot()
    {
        const string Config = """
            { "servers": {
                "open": { "command": "node", "args": ["server.js"], "env": { "SERVICE_API_KEY": "made-up-key", "LOG_LEVEL": "debug" } },
                "remote": { "type": "http", "url": "https://mcp.example.test/", "headers": { "Authorization": "Bearer made-up-token" } },
                "careful": { "command": "node", "args": ["server.js"], "env": { "SERVICE_API_KEY": "${input:service-key}" } } } }
            """;

        CheckOutcome outcome = Servers.Run(File(VsCodeMcp, Config));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("2 MCP servers run unpinned code, use plain HTTP or keep a secret in the open.", outcome.Summary);
        CollectionAssert.AreEqual(
            new[] { "VS Code: server \"open\"", "VS Code: server \"remote\"" }, outcome.Findings.Select(f => f.Item).ToArray());
        Assert.IsFalse(Everything(outcome).Contains("made-up", StringComparison.Ordinal));
    }

    [TestMethod]
    public void Servers_PlainHttpToAnotherMachine_Fails_AndToThisPcDoesNot()
    {
        CheckOutcome elsewhere = Servers.Run(File(VsCodeMcp, """{ "servers": { "remote": { "url": "http://mcp.example.test/sse" } } }"""));
        Assert.AreEqual("VS Code: server \"remote\": Reached over plain HTTP (expected HTTPS) [problem]", elsewhere.Rows()[0]);

        Assert.AreEqual(
            CheckStatus.Pass, Servers.Run(File(VsCodeMcp, """{ "servers": { "local": { "url": "http://localhost:3000/mcp" } } }""")).Status);
    }

    [TestMethod]
    public void Servers_ClaudeCode_AlsoKeepsThemPerProject_AndCodexInToml()
    {
        const string State = """
            { "numStartups": 12,
              "mcpServers": { "pinned": { "command": "npx", "args": ["-y", "some-server@1.2.3"] } },
              "projects": { "D:/work/project": { "mcpServers": { "floating": { "command": "uvx", "args": ["some-server"] } } } } }
            """;
        CheckOutcome claude = Servers.Run(File(ClaudeState, State));
        Assert.AreEqual(CheckStatus.Fail, claude.Status);
        Assert.AreEqual("Claude Code (one project): server \"floating\"", claude.Findings[0].Item);
        Assert.IsFalse(Everything(claude).Contains("D:/work", StringComparison.Ordinal), "the project's folder is not shown");

        const string Codex = "model = \"some-model\"\n\n[mcp_servers.docs]\ncommand = \"npx\"\nargs = [\"-y\", \"some-server\"]\n\n[mcp_servers.docs.env]\nSERVICE_TOKEN = \"made-up-token\"\n";
        CheckOutcome codex = Servers.Run(File(CodexConfig, Codex));
        Assert.AreEqual(2, codex.Findings.Count);
        Assert.AreEqual($"{CodexConfig}, line 3", codex.Findings[0].Source);
        Assert.IsFalse(Everything(codex).Contains("made-up", StringComparison.Ordinal));
    }

    [TestMethod]
    public void Servers_NoneSetUp_Pass_AndBrokenFilesAreCouldNotCheck()
    {
        Assert.AreEqual("No MCP servers are set up.", Servers.Run(File(ClaudeDesktop, """{ "mcpServers": {} }""")).Summary);
        Assert.AreEqual(CheckStatus.Error, Servers.Run(File(ClaudeDesktop, "{ not json")).Status);
        Assert.AreEqual("No MCP servers are set up.", Servers.Run(File(VsCodeMcp, string.Empty)).Summary, "an empty settings file sets nothing");
        Assert.AreEqual(CheckStatus.Pass, Permissions.Run(File(ClaudeSettings, "  ")).Status);

        FakeProbes both = File(ClaudeDesktop, "{ not json").WithFile(VsCodeMcp, """{ "servers": { "x": { "command": "npx", "args": ["some-server"] } } }""");
        Assert.AreEqual(CheckStatus.Fail, Servers.Run(both).Status, "a found problem still fails");
    }

    // What the reviews found

    [TestMethod]
    [DataRow("npx", new[] { "--registry", "https://registry.example.test", "some-server" })]
    [DataRow("npx", new[] { "-y", "some-server@1" })]
    [DataRow("npx", new[] { "-y", "some-server@1.2" })]
    [DataRow("npx", new[] { "-y", "some-server@1.x" })]
    [DataRow("cmd", new[] { "/d", "/s", "/c", "npx", "-y", "some-server" })]
    [DataRow("npm", new[] { "exec", "--", "some-server" })]
    [DataRow("docker", new[] { "run", "-e", "DIGEST=@sha256:0123", "--rm", "vendor/some-server:latest" })]
    public void Servers_UnpinnedCode_IsNotHiddenByOptionsOrPartialVersions(string command, string[] arguments)
    {
        Assert.AreEqual(CheckStatus.Fail, Servers.Run(Desktop(command, arguments)).Status);
    }

    [TestMethod]
    [DataRow("npx", new[] { "--registry", "https://registry.example.test", "some-server@1.2.3" })]
    [DataRow("docker", new[] { "run", "-e", "MODE=fast", "--rm", "vendor/some-server@sha256:0123456789abcdef" })]
    public void Servers_PinnedCode_StillPasses_WithOptionsBeforeIt(string command, string[] arguments)
    {
        Assert.AreEqual(CheckStatus.Pass, Servers.Run(Desktop(command, arguments)).Status);
    }

    [TestMethod]
    public void Servers_ClaudeCodesStateFile_FollowsItsFolderVariable_AndGeminisAddressNameIsRead()
    {
        FakeProbes moved = new FakeProbes()
            .WithRegistryValue(RegistryRoot.CurrentUser, PersistentEnvironment.UserKey, "CLAUDE_CONFIG_DIR", RegistryValue.FromText(@"D:\claude"))
            .WithFile(@"D:\claude\.claude.json", """{ "mcpServers": { "floating": { "command": "uvx", "args": ["some-server"] } } }""");
        Assert.AreEqual(CheckStatus.Fail, Servers.Run(moved).Status);

        CheckOutcome gemini = Servers.Run(File(GeminiSettings, """{ "mcpServers": { "remote": { "httpUrl": "http://mcp.example.test/mcp" } } }"""));
        Assert.AreEqual("Gemini CLI: server \"remote\": Reached over plain HTTP (expected HTTPS) [problem]", gemini.Rows()[0]);
    }

    [TestMethod]
    public void Servers_TheSameServerInSeveralProjects_IsShownOnce()
    {
        const string State = """
            { "projects": {
                "D:/work/one": { "mcpServers": { "floating": { "command": "uvx", "args": ["some-server"] } } },
                "D:/work/two": { "mcpServers": { "floating": { "command": "uvx", "args": ["some-server"] } } } } }
            """;

        CheckOutcome outcome = Servers.Run(File(ClaudeState, State));

        Assert.AreEqual(1, outcome.Findings.Count);
        Assert.AreEqual("1 MCP server runs unpinned code, uses plain HTTP or keeps a secret in the open.", outcome.Summary);
    }

    [TestMethod]
    public void Permissions_CodexsActiveProfile_ReplacesTheTopLevelValues()
    {
        const string Risky = "profile = \"fast\"\napproval_policy = \"on-request\"\n\n[profiles.fast]\napproval_policy = \"never\"\nsandbox_mode = \"danger-full-access\"\n";
        Assert.AreEqual(CheckStatus.Fail, Permissions.Run(File(CodexConfig, Risky)).Status);

        const string NotActive = "approval_policy = \"on-request\"\n\n[profiles.fast]\napproval_policy = \"never\"\nsandbox_mode = \"danger-full-access\"\n";
        Assert.AreEqual(CheckStatus.Pass, Permissions.Run(File(CodexConfig, NotActive)).Status);
    }

    // Approvals

    [TestMethod]
    public void Permissions_OrdinarySettings_Pass()
    {
        FakeProbes probes = File(ClaudeSettings, """{ "permissions": { "allow": ["Bash(git status)"], "defaultMode": "acceptEdits" }, "model": "some-model" }""")
            .WithFile(CodexConfig, "approval_policy = \"on-request\"\nsandbox_mode = \"workspace-write\"\n");

        CheckOutcome outcome = Permissions.Run(probes);

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("Claude Code and Codex ask before acting.", outcome.Summary);
    }

    [TestMethod]
    [DataRow("""{ "permissions": { "defaultMode": "bypassPermissions" } }""", "Claude Code: asking before it acts: off for every session.")]
    [DataRow("""{ "skipDangerousModePermissionPrompt": true }""", "Claude Code: warning before the no-asking mode: switched off.")]
    [DataRow("""{ "enableAllProjectMcpServers": true }""", "Claude Code: MCP servers that a project brings: started without asking.")]
    public void Permissions_ClaudeCodeSettingsThatSkipAsking_Fail(string settings, string summary)
    {
        CheckOutcome outcome = Permissions.Run(File(ClaudeSettings, settings));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual(summary, outcome.Summary);
    }

    [TestMethod]
    public void Permissions_Codex_FailsOnlyWithNoApprovalsAndNoSandboxTogether()
    {
        CheckOutcome both = Permissions.Run(File(CodexConfig, "approval_policy = \"never\"\nsandbox_mode = \"danger-full-access\"\n"));
        Assert.AreEqual("Codex: asking before it acts: off, with no sandbox.", both.Summary);

        Assert.AreEqual(
            CheckStatus.Pass, Permissions.Run(File(CodexConfig, "approval_policy = \"never\"\nsandbox_mode = \"workspace-write\"\n")).Status);
    }

    [TestMethod]
    public void Permissions_ATrustedGeminiServer_Fails_AndSeveralAreCounted()
    {
        FakeProbes probes = File(GeminiSettings, """{ "mcpServers": { "docs": { "command": "node", "trust": true }, "other": { "command": "node" } } }""")
            .WithFile(ClaudeSettings, """{ "permissions": { "defaultMode": "bypassPermissions" } }""");

        CheckOutcome outcome = Permissions.Run(probes);

        Assert.AreEqual("2 settings let AI tools act without asking.", outcome.Summary);
    }

    [TestMethod]
    public void Permissions_TheClaudeFolderCanBeMoved_AndBrokenFilesAreCouldNotCheck()
    {
        FakeProbes moved = new FakeProbes()
            .WithRegistryValue(RegistryRoot.CurrentUser, PersistentEnvironment.UserKey, "CLAUDE_CONFIG_DIR", RegistryValue.FromText(@"D:\claude"))
            .WithFile(@"D:\claude\settings.json", """{ "permissions": { "defaultMode": "bypassPermissions" } }""");
        Assert.AreEqual(CheckStatus.Fail, Permissions.Run(moved).Status);

        Assert.AreEqual(CheckStatus.Error, Permissions.Run(File(ClaudeSettings, "{ not json")).Status);
        Assert.AreEqual(CheckStatus.Error, Permissions.Run(File(CodexConfig, "approval_policy = never\n")).Status);
    }
}
