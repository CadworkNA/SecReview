using SecReview.Probing;

namespace SecReview.Checks.BuiltIn;

/// <summary>
/// When Microsoft Defender is the antivirus in use, its real-time, tamper and cloud-delivered
/// protection must be on. When another antivirus is in charge Defender steps back, and this
/// check does not apply; the antivirus check covers that product.
/// </summary>
public sealed class DefenderCheck : ICheck
{
    public const string Id = "defender.protection";

    internal const string WmiNamespace = @"ROOT\Microsoft\Windows\Defender";
    internal const string StatusClass = "MSFT_MpComputerStatus";
    internal const string PreferenceClass = "MSFT_MpPreference";

    private const string RealTime = "Real-time protection";
    private const string Tamper = "Tamper protection";
    private const string Cloud = "Cloud-delivered protection";

    /// <summary>MSFT_MpPreference.MAPSReporting: 0 disabled, 1 basic, 2 advanced.</summary>
    private const long CloudDisabled = 0;

    private static readonly string[] StatusProperties =
        ["AMRunningMode", "AntivirusEnabled", "RealTimeProtectionEnabled", "IsTamperProtected"];

    internal const string AttackSurfaceIds = "AttackSurfaceReductionRules_Ids";
    internal const string AttackSurfaceActions = "AttackSurfaceReductionRules_Actions";

    private const string CloudProperty = "MAPSReporting";

    /// <summary>
    /// The settings the Defender checks and rules read. They are asked for together, so that
    /// one scan asks Defender once however many checks look at its settings.
    /// </summary>
    private static readonly string[] SharedSettings =
    [
        CloudProperty,
        "PUAProtection",
        "DisableBehaviorMonitoring",
        "EnableNetworkProtection",
        "DisableIOAVProtection",
        "DisableScriptScanning",
        AttackSurfaceIds,
        AttackSurfaceActions,
    ];

    /// <summary>
    /// Defender's settings object. Asks the shared question when it covers what is wanted; if
    /// this version of Defender does not answer that (a setting it does not have), or other
    /// settings are wanted, asks for exactly those.
    /// </summary>
    private static ProbeResult<IReadOnlyList<WmiObject>> QuerySettings(IWmiProbe wmi, IReadOnlyList<string> wanted)
    {
        if (wanted.All(p => SharedSettings.Contains(p, StringComparer.OrdinalIgnoreCase)))
        {
            ProbeResult<IReadOnlyList<WmiObject>> shared = wmi.Query(WmiNamespace, PreferenceClass, SharedSettings);
            if (shared.IsOk || shared.Status == ProbeStatus.AccessDenied)
            {
                return shared;
            }
        }

        return wmi.Query(WmiNamespace, PreferenceClass, wanted);
    }

    /// <summary>
    /// Defender's settings, when it is the antivirus in use and they can be read. Otherwise the
    /// outcome for the check that wanted them.
    /// </summary>
    internal static CheckOutcome? ReadSettings(SystemProbes probes, IReadOnlyList<string> wanted, out WmiObject settings)
    {
        settings = null!;
        if (ReadStatus(probes, out _) is { } notInUse)
        {
            return notInUse;
        }

        ProbeResult<IReadOnlyList<WmiObject>> read = QuerySettings(probes.Wmi, wanted);
        if (!read.IsOk)
        {
            return ProbeOutcomes.FromFailure(read, "Microsoft Defender's settings");
        }

        if (read.Value!.Count == 0)
        {
            return CheckOutcome.Error("Microsoft Defender did not report its settings.");
        }

        settings = read.Value[0];
        return null;
    }

    /// <summary>
    /// Normally answered in full as a normal user. Where Defender's settings need administrator
    /// rights, the administrator scan reads them, so the check must be part of it.
    /// </summary>
    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SystemIntegrity, Severity.High, AdminNeed.ForFullDetail);

    /// <summary>
    /// Microsoft Defender's status, when it is the antivirus in use. Otherwise the outcome for
    /// every check about Defender: "does not apply" when it is absent or has stepped back for
    /// another antivirus, "could not check" when its status cannot be read.
    /// </summary>
    internal static CheckOutcome? ReadStatus(SystemProbes probes, out WmiObject status)
    {
        status = null!;
        ProbeResult<IReadOnlyList<WmiObject>> statusRead = probes.Wmi.Query(WmiNamespace, StatusClass, StatusProperties);
        if (statusRead.Status == ProbeStatus.NotSupported)
        {
            return CheckOutcome.NotApplicable("Microsoft Defender Antivirus is not part of this Windows.");
        }

        if (!statusRead.IsOk)
        {
            return ProbeOutcomes.FromFailure(statusRead, "the Microsoft Defender status");
        }

        if (statusRead.Value!.Count == 0)
        {
            return CheckOutcome.Error("Microsoft Defender did not report its status.");
        }

        status = statusRead.Value[0];
        string? mode = status.Text("AMRunningMode");
        if (status.Flag("AntivirusEnabled") == false ||
            (mode is not null && !mode.Equals("Normal", StringComparison.OrdinalIgnoreCase)))
        {
            return CheckOutcome.NotApplicable(
                "Microsoft Defender is not the antivirus in use; the antivirus check covers the one that is.");
        }

        return null;
    }

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (ReadStatus(context.Probes, out WmiObject status) is { } notInUse)
        {
            return notInUse;
        }

        var findings = new List<Finding>(3);
        var off = new List<string>(3);
        var unknown = new List<string>(3);

        Add(RealTime, "real-time protection", status.Flag("RealTimeProtectionEnabled"));
        Add(Tamper, "tamper protection", status.Flag("IsTamperProtected"));

        ProbeResult<IReadOnlyList<WmiObject>> preferences = QuerySettings(context.Probes.Wmi, [CloudProperty]);
        bool needsAdmin = preferences.Status == ProbeStatus.AccessDenied;
        long? cloud = preferences.IsOk && preferences.Value!.Count > 0 ? preferences.Value[0].Number(CloudProperty) : null;
        Add(Cloud, "cloud-delivered protection", cloud is null ? null : cloud != CloudDisabled);

        if (off.Count > 0)
        {
            return CheckOutcome.Fail($"Microsoft Defender's {Wording.JoinWithAnd(off)} {Wording.IsOrAre(off.Count)} off.", findings);
        }

        if (unknown.Count > 0)
        {
            string summary = $"Microsoft Defender did not report its {Wording.JoinWithAnd(unknown)}.";
            return needsAdmin && unknown.Count == 1
                ? CheckOutcome.NeedsAdmin("Reading Microsoft Defender's cloud-delivered protection needs administrator rights.", findings)
                : CheckOutcome.Error(summary, findings);
        }

        return CheckOutcome.Pass("Microsoft Defender's real-time, tamper and cloud-delivered protection are on.", findings);

        void Add(string item, string name, bool? on)
        {
            switch (on)
            {
                case true:
                    findings.Add(Finding.Ok(item, "On", "On"));
                    break;
                case false:
                    off.Add(name);
                    findings.Add(Finding.Problem(item, "Off", "On"));
                    break;
                default:
                    unknown.Add(name);
                    findings.Add(Finding.Problem(item, "Not reported", "On"));
                    break;
            }
        }
    }
}
