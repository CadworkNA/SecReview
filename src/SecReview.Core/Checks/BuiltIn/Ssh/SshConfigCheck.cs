namespace SecReview.Checks.BuiltIn.Ssh;

/// <summary>
/// The SSH client must not forward the agent to every host, and must not have host key checking
/// switched off for every host. Either setting for one named host is a deliberate choice and is
/// only listed. OpenSSH uses the first value it finds for a host, and so does this check.
/// </summary>
public sealed class SshConfigCheck : ICheck
{
    public const string Id = "ssh.config";

    private const string Forwarding = "Agent forwarding for every host";
    private const string HostKeys = "Host key checking for every host";

    private static readonly string[] DiscardingFiles = ["/dev/null", "nul", "none"];

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.Access, Severity.Medium, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        SshSettings read = SshConfigFile.Read(context.Probes);
        if (!read.AnyFile && read.Problem is null)
        {
            return CheckOutcome.NotApplicable("No SSH client settings file.");
        }

        IReadOnlyList<SshSetting> settings = read.Settings;
        int forwardAt = FirstForAllHosts(settings, "forwardagent");
        int strictAt = FirstForAllHosts(settings, "stricthostkeychecking");
        int knownHostsAt = FirstForAllHosts(settings, "userknownhostsfile");

        bool forwardsAll = forwardAt >= 0 && IsForwarding(settings[forwardAt].Value);
        bool checkingOff = strictAt >= 0 && IsCheckingOff(settings[strictAt].Value);
        bool hostsDiscarded = knownHostsAt >= 0 &&
            DiscardingFiles.Contains(settings[knownHostsAt].Value, StringComparer.OrdinalIgnoreCase);

        var findings = new List<Finding>
        {
            forwardsAll
                ? Finding.Problem(Forwarding, "On", "Off", settings[forwardAt].Source)
                : Finding.Ok(Forwarding, "Off", "Off", forwardAt >= 0 ? settings[forwardAt].Source : null),
            checkingOff
                ? Finding.Problem(HostKeys, "Off", "On", settings[strictAt].Source)
                : Finding.Ok(HostKeys, "On", "On", strictAt >= 0 ? settings[strictAt].Source : null),
        };
        if (hostsDiscarded)
        {
            findings.Add(Finding.Problem("Known hosts for every host", "Not remembered", "Remembered", settings[knownHostsAt].Source));
        }

        // Settings for named hosts only count where no earlier setting for every host overrides them.
        for (int i = 0; i < settings.Count; i++)
        {
            SshSetting setting = settings[i];
            if (setting.AllHosts)
            {
                continue;
            }

            if (setting.Keyword == "forwardagent" && IsForwarding(setting.Value) && (forwardAt < 0 || i < forwardAt))
            {
                findings.Add(Finding.Note($"Agent forwarding for \"{setting.Hosts}\"", "On", setting.Source));
            }
            else if (setting.Keyword == "stricthostkeychecking" && IsCheckingOff(setting.Value) && (strictAt < 0 || i < strictAt))
            {
                findings.Add(Finding.Note($"Host key checking for \"{setting.Hosts}\"", "Off", setting.Source));
            }
        }

        var problems = new List<string>(3);
        if (forwardsAll)
        {
            problems.Add("forwards your agent to every host");
        }

        if (checkingOff)
        {
            problems.Add("does not check host keys");
        }

        if (hostsDiscarded)
        {
            problems.Add("does not remember known hosts");
        }

        if (problems.Count > 0)
        {
            return CheckOutcome.Fail($"SSH {Wording.JoinWithAnd(problems)}.", findings);
        }

        // Part of the settings could not be read, so "nothing wrong" is not known.
        if (read.Problem is not null)
        {
            return CheckOutcome.Error(read.Problem, findings);
        }

        return CheckOutcome.Pass("SSH checks host keys and does not forward your agent everywhere.", findings);
    }

    private static int FirstForAllHosts(IReadOnlyList<SshSetting> settings, string keyword)
    {
        for (int i = 0; i < settings.Count; i++)
        {
            if (settings[i].AllHosts && settings[i].Keyword == keyword)
            {
                return i;
            }
        }

        return -1;
    }

    /// <summary>
    /// OpenSSH reads "no" and "false" as off; "yes", "true", a socket path or a variable name
    /// all forward an agent.
    /// </summary>
    private static bool IsForwarding(string value) =>
        value.Length > 0 &&
        !value.Equals("no", StringComparison.OrdinalIgnoreCase) &&
        !value.Equals("false", StringComparison.OrdinalIgnoreCase);

    /// <summary>OpenSSH reads "no", "false" and "off" as: accept any host key.</summary>
    private static bool IsCheckingOff(string value) =>
        value.Equals("no", StringComparison.OrdinalIgnoreCase) ||
        value.Equals("false", StringComparison.OrdinalIgnoreCase) ||
        value.Equals("off", StringComparison.OrdinalIgnoreCase);
}
