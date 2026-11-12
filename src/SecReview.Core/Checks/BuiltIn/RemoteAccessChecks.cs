using SecReview.Probing;

namespace SecReview.Checks.BuiltIn;

/// <summary>
/// Remote Desktop must be off, or on with Network Level Authentication, which makes callers
/// sign in before they get a session. A policy value decides when there is one.
/// </summary>
public sealed class RemoteDesktopCheck : ICheck
{
    public const string Id = "remote.desktop";

    internal const string PolicyKey = @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";
    internal const string LocalKey = @"SYSTEM\CurrentControlSet\Control\Terminal Server";
    internal const string ListenerKey = LocalKey + @"\WinStations\RDP-Tcp";
    internal const string DenyValue = "fDenyTSConnections";
    internal const string NlaValue = "UserAuthentication";

    private const string What = "the Remote Desktop setting";
    private const string Item = "Remote Desktop";
    private const string NlaItem = "Network Level Authentication";

    public CheckDefinition Definition { get; } = new(Id, CheckCategory.FirewallAndSharing, Severity.Medium);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        IRegistryProbe registry = context.Probes.Registry;

        if (RegistryReader.Number(registry, RegistryRoot.LocalMachine, PolicyKey, DenyValue, What, out long? policyDeny) is { } f1)
        {
            return f1;
        }

        if (RegistryReader.Number(registry, RegistryRoot.LocalMachine, LocalKey, DenyValue, What, out long? localDeny) is { } f2)
        {
            return f2;
        }

        bool byPolicy = policyDeny is not null;
        string source = byPolicy ? $@"HKLM\{PolicyKey}\{DenyValue}" : $@"HKLM\{LocalKey}\{DenyValue}";

        // Without either value Windows does not accept Remote Desktop connections.
        bool on = (policyDeny ?? localDeny ?? 1) == 0;
        if (!on)
        {
            string found = policyDeny is null && localDeny is null ? "Off (Windows default)" : "Off";
            return CheckOutcome.Pass("Remote Desktop is off.", Finding.Ok(Item, found, "Off", source)) with { ManagedByPolicy = byPolicy };
        }

        if (RegistryReader.Number(registry, RegistryRoot.LocalMachine, PolicyKey, NlaValue, What, out long? policyNla) is { } f3)
        {
            return f3;
        }

        if (RegistryReader.Number(registry, RegistryRoot.LocalMachine, ListenerKey, NlaValue, What, out long? localNla) is { } f4)
        {
            return f4;
        }

        bool nlaByPolicy = policyNla is not null;
        string nlaSource = nlaByPolicy ? $@"HKLM\{PolicyKey}\{NlaValue}" : $@"HKLM\{ListenerKey}\{NlaValue}";
        bool managed = byPolicy || nlaByPolicy;

        if (policyNla is null && localNla is null)
        {
            return CheckOutcome.Error(
                "Remote Desktop is on, but Windows does not say whether it requires Network Level Authentication.",
                Finding.Note(Item, "On", source)) with { ManagedByPolicy = managed };
        }

        bool nla = (policyNla ?? localNla) == 1;
        List<Finding> findings =
        [
            Finding.Note(Item, "On", source),
            nla ? Finding.Ok(NlaItem, "Required", "Required", nlaSource) : Finding.Problem(NlaItem, "Not required", "Required", nlaSource),
        ];

        return (nla
            ? CheckOutcome.Pass("Remote Desktop is on and requires Network Level Authentication.", findings)
            : CheckOutcome.Fail("Remote Desktop is on without Network Level Authentication.", findings))
            with { ManagedByPolicy = managed };
    }
}

/// <summary>
/// Services that let other computers run commands on this PC should not be running on a staff
/// PC: Windows Remote Management and the OpenSSH server.
/// </summary>
public sealed class RemoteServicesCheck : ICheck
{
    public const string Id = "remote.services";

    /// <summary>Service name and the name people know it by.</summary>
    internal static readonly (string Service, string Name)[] Services =
    [
        ("WinRM", "Windows Remote Management"),
        ("sshd", "OpenSSH server"),
    ];

    public CheckDefinition Definition { get; } = new(Id, CheckCategory.FirewallAndSharing, Severity.Medium);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var findings = new List<Finding>(Services.Length);
        var running = new List<string>();
        foreach ((string service, string name) in Services)
        {
            ProbeResult<ServiceInfo> info = context.Probes.Services.GetService(service);
            if (info.Status == ProbeStatus.NotFound)
            {
                findings.Add(Finding.Ok(name, "Not installed", "Not running"));
            }
            else if (!info.IsOk)
            {
                return ProbeOutcomes.FromFailure(info, $"the {name} service");
            }
            else if (info.Value!.IsRunning)
            {
                running.Add(name);
                findings.Add(Finding.Problem(name, "Running", "Not running"));
            }
            else
            {
                findings.Add(Finding.Ok(name, "Not running", "Not running"));
            }
        }

        return running.Count > 0
            ? CheckOutcome.Fail($"{Wording.JoinWithAnd(running)} {Wording.IsOrAre(running.Count)} running.", findings)
            : CheckOutcome.Pass("No remote management service is running.", findings);
    }
}

/// <summary>
/// Folders shared on the network are listed, since each is reachable by other computers. The
/// shares Windows creates for its own administration are left out. Share names can be personal,
/// so only how many there are is reported.
/// </summary>
public sealed class SharedFoldersCheck : ICheck
{
    public const string Id = "sharing.folders";

    internal const string WmiNamespace = @"ROOT\CIMV2";
    internal const string WmiClass = "Win32_Share";

    /// <summary>Win32_Share.Type: a disk share. Administrative shares have the top bit set as well.</summary>
    private const long DiskShare = 0;

    /// <summary>The share Windows adds when a printer is shared; it holds printer drivers only.</summary>
    private const string PrinterDrivers = "print$";

    private static readonly string[] Properties = ["Name", "Type"];

    public CheckDefinition Definition { get; } = new(Id, CheckCategory.FirewallAndSharing, Severity.Low);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        ProbeResult<IReadOnlyList<WmiObject>> shares = context.Probes.Wmi.Query(WmiNamespace, WmiClass, Properties);
        if (!shares.IsOk)
        {
            return ProbeOutcomes.FromFailure(shares, "the shared folders");
        }

        int unknown = shares.Value!.Count(s => s.Number("Type") is null);
        if (unknown > 0)
        {
            return CheckOutcome.Error("Windows listed shares without saying what kind they are.");
        }

        int folders = shares.Value!.Count(s =>
            s.Number("Type") == DiskShare && !string.Equals(s.Text("Name"), PrinterDrivers, StringComparison.OrdinalIgnoreCase));

        return folders == 0
            ? CheckOutcome.Pass("No folders are shared on the network.", Finding.Ok("Shared folders", "None", "None"))
            : CheckOutcome.Fail(
                folders == 1 ? "1 folder is shared on the network." : $"{folders} folders are shared on the network.",
                Finding.Problem("Shared folders", folders.ToString(System.Globalization.CultureInfo.InvariantCulture), "None"));
    }
}

/// <summary>
/// The two accounts every Windows PC has, Guest and the built-in Administrator, must be
/// disabled: their names are known to every attacker. They are recognised by their fixed
/// identifiers, so renaming them changes nothing. Account names are not reported.
/// </summary>
public sealed class BuiltInAccountsCheck : ICheck
{
    public const string Id = "accounts.builtin";

    internal const string WmiNamespace = @"ROOT\CIMV2";
    internal const string WmiClass = "Win32_UserAccount";

    private static readonly string[] Properties = ["SID", "Disabled", "LocalAccount"];

    /// <summary>Only local accounts: without this the query would list a whole domain.</summary>
    internal static readonly WmiFlagFilter LocalOnly = new("LocalAccount", true);

    public CheckDefinition Definition { get; } = new(Id, CheckCategory.Access, Severity.Medium);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        ProbeResult<IReadOnlyList<WmiObject>> accounts =
            context.Probes.Wmi.Query(WmiNamespace, WmiClass, Properties, LocalOnly);
        if (!accounts.IsOk)
        {
            return ProbeOutcomes.FromFailure(accounts, "the local accounts");
        }

        bool? administratorDisabled = Disabled(accounts.Value!, "-500");
        bool? guestDisabled = Disabled(accounts.Value!, "-501");
        if (administratorDisabled is null || guestDisabled is null)
        {
            return CheckOutcome.Error("Windows did not list the built-in Administrator and Guest accounts.");
        }

        List<Finding> findings =
        [
            Row("Built-in Administrator account", administratorDisabled.Value),
            Row("Guest account", guestDisabled.Value),
        ];

        return (administratorDisabled.Value, guestDisabled.Value) switch
        {
            (true, true) => CheckOutcome.Pass("The built-in Administrator and Guest accounts are disabled.", findings),
            (false, false) => CheckOutcome.Fail("The built-in Administrator and Guest accounts are enabled.", findings),
            (false, true) => CheckOutcome.Fail("The built-in Administrator account is enabled.", findings),
            _ => CheckOutcome.Fail("The Guest account is enabled.", findings),
        };
    }

    private static Finding Row(string item, bool disabled) => disabled
        ? Finding.Ok(item, "Disabled", "Disabled")
        : Finding.Problem(item, "Enabled", "Disabled");

    /// <summary>Whether the account whose identifier ends this way is disabled; null if it was not listed.</summary>
    private static bool? Disabled(IReadOnlyList<WmiObject> accounts, string identifierEnd) =>
        accounts.FirstOrDefault(a => a.Text("SID")?.EndsWith(identifierEnd, StringComparison.Ordinal) == true)?.Flag("Disabled");
}
