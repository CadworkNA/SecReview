using System.Globalization;
using System.Text.Json;
using SecReview.Checks;
using SecReview.Config;
using SecReview.Probing;

namespace SecReview.SupplyChain.Credentials;

/// <summary>The folders these checks start from, and the variables that move a tool's files.</summary>
internal static class CredentialPlaces
{
    public static CheckOutcome? Folders(SystemProbes probes, out string profile, out string roaming)
    {
        ProbeResult<string> user = probes.Environment.Folder(KnownFolder.UserProfile);
        ProbeResult<string> appData = probes.Environment.Folder(KnownFolder.RoamingAppData);
        (profile, roaming) = (user.Value ?? string.Empty, appData.Value ?? string.Empty);
        return user.IsOk && appData.IsOk ? null : CheckOutcome.Error("Windows did not say where your user folders are.");
    }

    /// <summary>A folder or file a variable names, else the usual one.</summary>
    public static CheckOutcome? Moved(SystemProbes probes, string variable, string usual, out string place)
    {
        place = usual;
        if (PersistentEnvironment.Read(probes, variable, out string? value, out _) is { } failed)
        {
            return failed;
        }

        if (!string.IsNullOrWhiteSpace(value))
        {
            place = value.Trim().Replace('/', '\\').TrimEnd('\\');
        }

        return null;
    }
}

/// <summary>
/// Docker must not keep registry passwords in its plain settings file. With a credential
/// store configured (Docker Desktop sets one up), the file holds only the registry's name;
/// without one, <c>docker login</c> writes the password there, merely encoded.
/// </summary>
public sealed class DockerCredentialsCheck : ICheck
{
    public const string Id = "sc.docker.credentials";

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.Medium, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        SystemProbes probes = context.Probes;

        if (CredentialPlaces.Folders(probes, out string profile, out _) is { } failed)
        {
            return failed;
        }

        if (CredentialPlaces.Moved(probes, "DOCKER_CONFIG", $@"{profile}\.docker", out string folder) is { } unread)
        {
            return unread;
        }

        var found = new SecretFindings();
        string path = $@"{folder}\config.json";
        if (found.LoadJson(probes.Files, path) is { } config && config.TryGetProperty("auths", out JsonElement auths) &&
            auths.ValueKind == JsonValueKind.Object)
        {
            foreach (JsonProperty registry in auths.EnumerateObject())
            {
                if (SecretFindings.HasLiteral(registry.Value, "auth") || SecretFindings.HasLiteral(registry.Value, "identitytoken") ||
                    SecretFindings.HasLiteral(registry.Value, "password"))
                {
                    found.Add($"Sign-in for {SecretFindings.Host(registry.Name)}", $"{path} (auths)");
                }
            }
        }

        return found.Outcome("Docker", "registry sign-ins", "Docker is not set up for this user.");
    }
}

/// <summary>
/// Docker must not skip TLS for a registry (<c>insecure-registries</c>) or open its control
/// port on the network without client certificates: whoever reaches that port controls the
/// PC. The engine's <c>daemon.json</c> and Docker Desktop's settings are read.
/// </summary>
public sealed class DockerSettingsCheck : ICheck
{
    public const string Id = "sc.docker.settings";

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.High, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        SystemProbes probes = context.Probes;

        if (CredentialPlaces.Folders(probes, out string profile, out string roaming) is { } failed)
        {
            return failed;
        }

        ProbeResult<string> programData = probes.Environment.Folder(KnownFolder.ProgramData);
        if (!programData.IsOk)
        {
            return CheckOutcome.Error("Windows did not say where its shared folder is.");
        }

        var files = new SecretFindings();
        var problems = new List<Finding>();

        foreach (string path in (string[])[$@"{profile}\.docker\daemon.json", $@"{programData.Value}\docker\config\daemon.json"])
        {
            if (files.LoadJson(probes.Files, path) is not { } daemon)
            {
                continue;
            }

            if (daemon.TryGetProperty("insecure-registries", out JsonElement insecure) && insecure.ValueKind == JsonValueKind.Array &&
                insecure.GetArrayLength() > 0)
            {
                problems.Add(Finding.Problem(
                    "Registries exempt from TLS checks", insecure.GetArrayLength().ToString(CultureInfo.InvariantCulture), "None", $"{path} (insecure-registries)"));
            }

            bool verifiesClients = daemon.TryGetProperty("tlsverify", out JsonElement verify) && verify.ValueKind == JsonValueKind.True;
            if (!verifiesClients && daemon.TryGetProperty("hosts", out JsonElement hosts) && hosts.ValueKind == JsonValueKind.Array &&
                hosts.EnumerateArray().Any(h => h.ValueKind == JsonValueKind.String && h.GetString()!.TrimStart().StartsWith("tcp://", StringComparison.OrdinalIgnoreCase)))
            {
                problems.Add(Finding.Problem("Control port", "Open over TCP without client certificates", "Closed", $"{path} (hosts)"));
            }
        }

        // Docker Desktop: "Expose daemon on tcp://localhost:2375 without TLS".
        foreach (string path in (string[])[$@"{roaming}\Docker\settings-store.json", $@"{roaming}\Docker\settings.json"])
        {
            if (files.LoadJson(probes.Files, path) is { } desktop &&
                desktop.EnumerateObject().Any(p => p.Name.Equals("ExposeDockerAPIOnTCP2375", StringComparison.OrdinalIgnoreCase) && p.Value.ValueKind == JsonValueKind.True))
            {
                problems.Add(Finding.Problem("Control port", "Open on TCP 2375 without sign-in", "Closed", path));
            }
        }

        if (problems.Count > 0)
        {
            return CheckOutcome.Fail(
                problems.Count == 1
                    ? $"Docker: {Wording.LowerFirst(problems[0].Item)}: {Wording.LowerFirst(problems[0].Found)}."
                    : $"Docker has {problems.Count} settings that weaken it.",
                problems);
        }

        if (files.Unreadable is { } problem)
        {
            return CheckOutcome.Error(problem);
        }

        return files.AnyFile
            ? CheckOutcome.Pass(
                "Docker checks TLS for every registry and keeps its control port closed.",
                Finding.Ok("Registries exempt from TLS checks", "None", "None"),
                Finding.Ok("Control port", "Not opened by these settings", "Closed"))
            : CheckOutcome.NotApplicable("Docker is not set up on this PC.");
    }
}

/// <summary>
/// The GitHub command-line tool keeps its token in Windows' credential store by default. A
/// token in its plain <c>hosts.yml</c> file (older versions, or <c>--insecure-storage</c>) is
/// readable by every program the user runs.
/// </summary>
public sealed class GitHubCliCredentialsCheck : ICheck
{
    public const string Id = "sc.github.credentials";

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

        // Where gh looks: GH_CONFIG_DIR, then "gh" under XDG_CONFIG_HOME, then its folder in the user's application data.
        if (CredentialPlaces.Moved(probes, "XDG_CONFIG_HOME", string.Empty, out string configHome) is { } unreadHome)
        {
            return unreadHome;
        }

        string usual = configHome.Length > 0 ? $@"{configHome}\gh" : $@"{roaming}\GitHub CLI";
        if (CredentialPlaces.Moved(probes, "GH_CONFIG_DIR", usual, out string folder) is { } unread)
        {
            return unread;
        }

        var found = new SecretFindings();
        if (found.Load(probes.Files, $@"{folder}\hosts.yml", SettingsFormat.Yaml) is { } file)
        {
            foreach ((string host, ConfigNode node) in file.Root!.Entries)
            {
                if (node is not ConfigMap settings)
                {
                    continue;
                }

                // The token sits at the top of a host's entry, and again per signed-in user.
                ConfigNode? token = SecretFindings.IsLiteral(settings["oauth_token"])
                    ? settings["oauth_token"]
                    : (settings["users"] as ConfigMap)?.Entries
                        .Select(user => (user.Value as ConfigMap)?["oauth_token"])
                        .FirstOrDefault(SecretFindings.IsLiteral);
                if (token is not null)
                {
                    found.Add($"Token for {SecretFindings.Host(host)}", file.At(token));
                }
            }
        }

        return found.Outcome("GitHub CLI", "tokens", "The GitHub command-line tool is not set up for this user.");
    }
}

/// <summary>
/// Cloud tools must not keep long-lived keys and tokens in plain files: AWS access keys in
/// <c>.aws\credentials</c> (keys with a session token expire by themselves and are not
/// counted), fixed tokens and passwords in the Kubernetes settings, Terraform tokens, and the
/// Azure CLI's old plain token cache.
/// </summary>
public sealed class CloudCredentialsCheck : ICheck
{
    public const string Id = "sc.cloud.credentials";

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.High, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        SystemProbes probes = context.Probes;

        if (CredentialPlaces.Folders(probes, out string profile, out string roaming) is { } failed)
        {
            return failed;
        }

        var found = new SecretFindings();

        // AWS: a section per profile. pip-style reading turns "_" in key names into "-".
        if (CredentialPlaces.Moved(probes, "AWS_SHARED_CREDENTIALS_FILE", $@"{profile}\.aws\credentials", out string awsPath) is { } unreadAws)
        {
            return unreadAws;
        }

        if (found.Load(probes.Files, awsPath, SettingsFormat.PythonIni) is { } aws)
        {
            foreach ((string name, ConfigNode node) in aws.Root!.Entries)
            {
                if (node is ConfigMap section && section["aws-secret-access-key"] is { } key && SecretFindings.IsLiteral(key) &&
                    !SecretFindings.IsLiteral(section["aws-session-token"]))
                {
                    found.Add($"AWS access key (profile \"{name}\")", aws.At(key));
                }
            }
        }

        // Kubernetes: users with a fixed token or password. Names may be account names, so entries are numbered.
        if (CredentialPlaces.Moved(probes, "KUBECONFIG", $@"{profile}\.kube\config", out string kubePath) is { } unreadKube)
        {
            return unreadKube;
        }

        // The variable may list several files, which kubectl merges; each is read.
        foreach (string path in kubePath.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            if (found.Load(probes.Files, path, SettingsFormat.Yaml) is not { } kube || kube.Root!["users"] is not ConfigList users)
            {
                continue;
            }

            int number = 0;
            foreach (ConfigNode entry in users.Items)
            {
                number++;
                ConfigMap? user = (entry as ConfigMap)?["user"] as ConfigMap;
                ConfigNode? secret = SecretFindings.IsLiteral(user?["token"]) ? user!["token"]
                    : SecretFindings.IsLiteral(user?["password"]) ? user!["password"]
                    : null;
                if (secret is not null)
                {
                    found.Add($"Kubernetes sign-in (user entry {number})", kube.At(secret));
                }
            }
        }

        // Terraform: tokens per host, written by "terraform login".
        string terraform = $@"{roaming}\terraform.d\credentials.tfrc.json";
        if (found.LoadJson(probes.Files, terraform) is { } tokens && tokens.TryGetProperty("credentials", out JsonElement hosts) &&
            hosts.ValueKind == JsonValueKind.Object)
        {
            foreach (JsonProperty host in hosts.EnumerateObject())
            {
                if (SecretFindings.HasLiteral(host.Value, "token"))
                {
                    found.Add($"Terraform token for {SecretFindings.Host(host.Name)}", $"{terraform} (credentials)");
                }
            }
        }

        // Azure CLI before 2.30 kept its tokens in a plain file; a non-empty one is still usable.
        string azure = $@"{profile}\.azure\accessTokens.json";
        JsonElement? cache = SettingsFiles.LoadJson(probes.Files, azure, out string? azureProblem);
        if (azureProblem is not null || cache is not null)
        {
            found.SawFile(azureProblem);
        }

        if (cache is { ValueKind: JsonValueKind.Array } list && list.GetArrayLength() > 0)
        {
            found.Add("Azure CLI token cache (old format)", azure);
        }

        return found.Outcome("Cloud tools", "access keys or tokens", "No cloud command-line tools are set up for this user.");
    }
}

/// <summary>
/// Build tools must not keep repository passwords and publishing keys in plain files: Maven's
/// <c>settings.xml</c> (unless encrypted by Maven), <c>gradle.properties</c>, RubyGems'
/// <c>credentials</c> and Composer's <c>auth.json</c>.
/// </summary>
public sealed class BuildCredentialsCheck : ICheck
{
    public const string Id = "sc.build.credentials";

    /// <summary>Words in a Gradle property's name that say it holds a secret.</summary>
    private static readonly string[] SecretWords = ["password", "passwd", "token", "secret", "apikey", "api_key", "api.key"];

    /// <summary>Endings that say the property names a file or an id instead.</summary>
    private static readonly string[] PointerEndings = ["file", "path", "id", "name", "user", "username"];

    /// <summary>Composer's sign-in sections: each is a map of host to a token or to named parts.</summary>
    private static readonly string[] ComposerSections = ["http-basic", "github-oauth", "gitlab-oauth", "gitlab-token", "bitbucket-oauth", "bearer"];

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.Medium, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        SystemProbes probes = context.Probes;

        if (CredentialPlaces.Folders(probes, out string profile, out string roaming) is { } failed)
        {
            return failed;
        }

        var found = new SecretFindings();

        // Maven: <servers><server><password>, and the same under <proxies>. "{...}" is Maven's own encryption.
        if (found.LoadXml(probes.Files, $@"{profile}\.m2\settings.xml") is { } maven)
        {
            foreach ((string group, string item) in new[] { ("servers", "server"), ("proxies", "proxy") })
            {
                foreach (MarkupElement entry in maven.Root!.Child(group)?.ChildrenNamed(item) ?? [])
                {
                    foreach (string secret in (string[])["password", "passphrase"])
                    {
                        if (entry.Child(secret) is { } element && SecretFindings.IsLiteral(element.Text) && !IsMavenEncrypted(element.Text))
                        {
                            string id = entry.Child("id")?.Text is { Length: > 0 } named ? $" \"{named}\"" : string.Empty;
                            found.Add($"Maven {secret} for {item}{id}", maven.At(element));
                        }
                    }
                }
            }
        }

        // Gradle: properties whose name says "secret".
        if (CredentialPlaces.Moved(probes, "GRADLE_USER_HOME", $@"{profile}\.gradle", out string gradleHome) is { } unreadGradle)
        {
            return unreadGradle;
        }

        string gradlePath = $@"{gradleHome}\gradle.properties";
        ProbeResult<string> gradle = probes.Files.ReadText(gradlePath);
        if (gradle.IsOk)
        {
            found.SawFile();
            foreach (PropertyEntry property in PropertiesReader.Read(gradle.Value!))
            {
                if (NamesASecret(property.Key) && SecretFindings.IsLiteral(property.Value))
                {
                    found.Add($"Gradle property {property.Key}", $"{gradlePath}, line {property.Line}");
                }
            }
        }
        else if (gradle.Status != ProbeStatus.NotFound)
        {
            found.SawFile("gradle.properties could not be read.");
        }

        // RubyGems: every entry of the file is a key.
        if (found.Load(probes.Files, $@"{profile}\.gem\credentials", SettingsFormat.Yaml) is { } gems)
        {
            foreach ((string name, ConfigNode value) in gems.Root!.Entries)
            {
                if (SecretFindings.IsLiteral(value))
                {
                    found.Add($"RubyGems key \"{name.TrimStart(':')}\"", gems.At(value));
                }
            }
        }

        // Composer: host -> token, or host -> { username, password }.
        if (CredentialPlaces.Moved(probes, "COMPOSER_HOME", $@"{roaming}\Composer", out string composerHome) is { } unreadComposer)
        {
            return unreadComposer;
        }

        string composerPath = $@"{composerHome}\auth.json";
        if (found.LoadJson(probes.Files, composerPath) is { } composer)
        {
            foreach (string section in ComposerSections)
            {
                if (!composer.TryGetProperty(section, out JsonElement hosts) || hosts.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                foreach (JsonProperty host in hosts.EnumerateObject())
                {
                    bool literal = host.Value.ValueKind switch
                    {
                        JsonValueKind.String => SecretFindings.IsLiteral(host.Value.GetString()),
                        JsonValueKind.Object => host.Value.EnumerateObject().Any(p =>
                            !p.Name.Equals("username", StringComparison.OrdinalIgnoreCase) && p.Value.ValueKind == JsonValueKind.String &&
                            SecretFindings.IsLiteral(p.Value.GetString())),
                        _ => false,
                    };
                    if (literal)
                    {
                        found.Add($"Composer sign-in for {SecretFindings.Host(host.Name)}", $"{composerPath} ({section})");
                    }
                }
            }
        }

        return found.Outcome("Build tools", "passwords or tokens", "No Maven, Gradle, RubyGems or Composer settings are in your user folder.");
    }

    /// <summary>Maven's encrypted passwords are wrapped in braces: "{COQLCE6DU6GtcS5P=}".</summary>
    private static bool IsMavenEncrypted(string value)
    {
        string text = value.Trim();
        return text.Length > 2 && text[0] == '{' && text[^1] == '}';
    }

    internal static bool NamesASecret(string key)
    {
        string name = key.ToLowerInvariant();
        return SecretWords.Any(word => name.Contains(word, StringComparison.Ordinal)) &&
            !PointerEndings.Any(ending => name.EndsWith(ending, StringComparison.Ordinal));
    }
}
