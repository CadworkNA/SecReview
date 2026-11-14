using System.Buffers.Binary;
using SecReview.Probing;

namespace SecReview.Checks.BuiltIn;

/// <summary>
/// Windows must ask whether a certificate was revoked, for signed programs and for websites.
/// Both questions can be switched off for one user under Internet Options; a stolen and
/// revoked certificate is then still accepted.
/// </summary>
public sealed class RevocationCheck : ICheck
{
    public const string Id = "system.revocation";

    internal const string PublisherKey = @"Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing";
    internal const string PublisherValue = "State";

    /// <summary>The bit of <see cref="PublisherValue"/> that says "do not ask about revocation".</summary>
    internal const long IgnoreRevocation = 0x200;

    internal const string ServerKey = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    internal const string ServerPolicyKey = @"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings";
    internal const string ServerValue = "CertificateRevocation";

    private const string PublisherItem = "Revocation check for signed programs";
    private const string ServerItem = "Revocation check for websites";
    private const string Default = "On (Windows default)";

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.Hardening, Severity.Medium, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        IRegistryProbe registry = context.Probes.Registry;

        if (RegistryReader.Number(
                registry, RegistryRoot.CurrentUser, PublisherKey, PublisherValue, "the revocation setting for signed programs", out long? state) is { } failed)
        {
            return failed;
        }

        // A policy, for the PC or the user, wins over the user's own setting.
        (RegistryRoot Root, string Key)[] places =
        [
            (RegistryRoot.LocalMachine, ServerPolicyKey), (RegistryRoot.CurrentUser, ServerPolicyKey), (RegistryRoot.CurrentUser, ServerKey),
        ];
        long? server = null;
        string serverSource = $@"HKCU\{ServerKey}\{ServerValue}";
        bool managed = false;
        foreach ((RegistryRoot root, string key) in places)
        {
            if (RegistryReader.Number(registry, root, key, ServerValue, "the revocation setting for websites", out server) is { } unread)
            {
                return unread;
            }

            if (server is not null)
            {
                serverSource = $@"{(root == RegistryRoot.LocalMachine ? "HKLM" : "HKCU")}\{key}\{ServerValue}";
                managed = key == ServerPolicyKey;
                break;
            }
        }

        bool publisherOff = state is { } bits && (bits & IgnoreRevocation) != 0;
        bool serverOff = server == 0;
        string publisherSource = $@"HKCU\{PublisherKey}\{PublisherValue}";

        List<Finding> findings =
        [
            publisherOff
                ? Finding.Problem(PublisherItem, "Off", "On", publisherSource)
                : Finding.Ok(PublisherItem, state is null ? Default : "On", "On", publisherSource),
            serverOff
                ? Finding.Problem(ServerItem, "Off", "On", serverSource)
                : Finding.Ok(ServerItem, server is null ? Default : "On", "On", serverSource),
        ];

        if (!publisherOff && !serverOff)
        {
            return CheckOutcome.Pass("Windows checks whether certificates were revoked.", findings);
        }

        string what = (publisherOff, serverOff) switch
        {
            (true, true) => "certificates of signed programs and websites",
            (true, false) => "certificates of signed programs",
            _ => "certificates of websites",
        };
        return CheckOutcome.Fail($"Windows does not check whether {what} were revoked.", findings) with { ManagedByPolicy = serverOff && managed };
    }
}

/// <summary>
/// A proxy configuration script decides where a user's web traffic goes. Fetched over plain
/// HTTP, it can be swapped on the network by anyone between the PC and the server. A fixed
/// proxy is listed by host for the user to recognise, and automatic proxy detection as on or
/// off; neither is judged. Detection is on by default, and whether someone on the network
/// can answer it cannot be told from the PC.
/// </summary>
public sealed class ProxyCheck : ICheck
{
    public const string Id = "network.proxy";

    internal const string UserKey = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    internal const string PolicyKey = @"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings";
    internal const string ScriptValue = "AutoConfigURL";
    internal const string EnabledValue = "ProxyEnable";
    internal const string ServerValue = "ProxyServer";
    internal const string ConnectionsKey = UserKey + @"\Connections";
    internal const string ConnectionsValue = "DefaultConnectionSettings";

    /// <summary>The bit of the flags in <see cref="ConnectionsValue"/> that says "detect settings automatically".</summary>
    internal const uint AutoDetect = 0x08;

    private const int FlagsOffset = 8;

    private const string ScriptItem = "Proxy configuration script";
    private const string Expected = "None, or fetched over HTTPS";

    /// <summary>
    /// Where the settings can be: a policy for the PC or the user, the PC when it has one
    /// setting for all users, the user. Which of them Windows uses depends on a policy; a
    /// script address in any of them is judged, and the result names the place.
    /// </summary>
    private static readonly (RegistryRoot Root, string Key)[] Places =
    [
        (RegistryRoot.LocalMachine, PolicyKey), (RegistryRoot.CurrentUser, PolicyKey), (RegistryRoot.LocalMachine, UserKey), (RegistryRoot.CurrentUser, UserKey),
    ];

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.FirewallAndSharing, Severity.Low, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        IRegistryProbe registry = context.Probes.Registry;

        var findings = new List<Finding>();
        bool managed = false;
        foreach ((RegistryRoot root, string key) in Places)
        {
            string source = $@"{(root == RegistryRoot.LocalMachine ? "HKLM" : "HKCU")}\{key}";
            if (RegistryReader.Text(registry, root, key, ScriptValue, "the proxy settings", out string? script) is { } failed)
            {
                return failed;
            }

            if (script is not null)
            {
                bool plain = script.StartsWith("http://", StringComparison.OrdinalIgnoreCase);
                managed |= plain && key == PolicyKey;
                findings.Add(plain
                    ? Finding.Problem(ScriptItem, $"Fetched over plain HTTP from {Host(script)}", Expected, $@"{source}\{ScriptValue}")
                    : Finding.Ok(ScriptItem, $"Fetched from {Host(script)}", Expected, $@"{source}\{ScriptValue}"));
            }

            if (RegistryReader.Number(registry, root, key, EnabledValue, "the proxy settings", out long? enabled) is { } unread)
            {
                return unread;
            }

            if (RegistryReader.Text(registry, root, key, ServerValue, "the proxy settings", out string? server) is { } unreadServer)
            {
                return unreadServer;
            }

            if (enabled is 1 && server is not null)
            {
                findings.Add(Finding.Note("Fixed proxy", Host(server), $@"{source}\{ServerValue}"));
            }
        }

        // Read as stored; a value that is not the expected shape is left out, as it is not judged.
        ProbeResult<RegistryValue> connections = registry.GetValue(RegistryRoot.CurrentUser, ConnectionsKey, ConnectionsValue);
        if (!connections.IsOk && connections.Status != ProbeStatus.NotFound)
        {
            return ProbeOutcomes.FromFailure(connections, "the proxy settings");
        }

        if (connections.IsOk && connections.Value!.Type == RegistryValueType.Binary && connections.Value.Binary.Length >= FlagsOffset + 4)
        {
            uint flags = BinaryPrimitives.ReadUInt32LittleEndian(connections.Value.Binary.Span[FlagsOffset..]);
            findings.Add(Finding.Note("Automatic proxy detection", (flags & AutoDetect) != 0 ? "On" : "Off", $@"HKCU\{ConnectionsKey}\{ConnectionsValue}"));
        }

        if (findings.Any(finding => finding.Status == FindingStatus.Problem))
        {
            return CheckOutcome.Fail("The proxy configuration script is fetched over plain HTTP.", findings) with { ManagedByPolicy = managed };
        }

        if (!findings.Any(finding => finding.Item == ScriptItem))
        {
            findings.Insert(0, Finding.Ok(ScriptItem, "None", Expected, $@"HKCU\{UserKey}\{ScriptValue}"));
        }

        return CheckOutcome.Pass(
            findings.Any(finding => finding.Item == ScriptItem && finding.Found != "None")
                ? "The proxy configuration script is fetched over a protected connection."
                : "No proxy configuration script is set.",
            findings);
    }

    /// <summary>
    /// The host of a script address or of a proxy ("host:port", "http=host:port;https=host:port"):
    /// never the path, a user name or anything else the text may carry.
    /// </summary>
    internal static string Host(string text)
    {
        string first = text.Trim().Split(';', 2)[0];
        int equals = first.IndexOf('=', StringComparison.Ordinal);
        int scheme = first.IndexOf("://", StringComparison.Ordinal);
        if (equals >= 0 && (scheme < 0 || equals < scheme))
        {
            // "https=host:port": the part before "=" says which traffic the proxy is for.
            first = first[(equals + 1)..];
            scheme = first.IndexOf("://", StringComparison.Ordinal);
        }

        first = scheme < 0 ? first : first[(scheme + 3)..];
        first = first.Split('/', 2)[0];
        int at = first.LastIndexOf('@');
        first = at < 0 ? first : first[(at + 1)..];

        // "[::1]:8080" keeps its brackets; otherwise the port goes.
        int port = first.LastIndexOf(':');
        if (port > 0 && !first.EndsWith(']') && first[(port + 1)..].All(char.IsAsciiDigit))
        {
            first = first[..port];
        }

        return first.Length is > 0 and <= 253 && first.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_' or ':' or '[' or ']')
            ? first
            : "one address";
    }
}
