namespace SecReview.Probing;

/// <summary>
/// Keeps the answer of readings that several checks share (the update service, the power
/// plan, how Windows was started) for the length of one scan, so each is asked once. A new
/// scan gets a new cache, so "check again" always reads afresh. A failed reading is kept
/// too: every check that depends on it then reports the same reason.
/// </summary>
public static class ScanCache
{
    /// <summary>The same probes, with the shared readings remembered. Use one per scan.</summary>
    public static SystemProbes ForOneScan(SystemProbes probes)
    {
        ArgumentNullException.ThrowIfNull(probes);
        return probes with
        {
            WindowsUpdate = new CachedWindowsUpdateProbe(probes.WindowsUpdate),
            Power = new CachedPowerProbe(probes.Power),
            Platform = new CachedPlatformProbe(probes.Platform),
            AccountPolicy = new CachedAccountPolicyProbe(probes.AccountPolicy),
            Wmi = new CachedWmiProbe(probes.Wmi),
        };
    }

    private sealed class CachedAccountPolicyProbe(IAccountPolicyProbe inner) : IAccountPolicyProbe
    {
        private readonly Lazy<ProbeResult<AccountPolicy>> _policy = new(inner.GetPolicy);

        public ProbeResult<AccountPolicy> GetPolicy() => _policy.Value;
    }

    /// <summary>The same question (namespace, class, properties, filter) is asked of WMI once.</summary>
    private sealed class CachedWmiProbe(IWmiProbe inner) : IWmiProbe
    {
        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, Lazy<ProbeResult<IReadOnlyList<WmiObject>>>> _answers =
            new(StringComparer.OrdinalIgnoreCase);

        public ProbeResult<IReadOnlyList<WmiObject>> Query(
            string wmiNamespace, string className, IReadOnlyList<string> properties, WmiFlagFilter? only = null)
        {
            ArgumentNullException.ThrowIfNull(properties);
            string question = $"{wmiNamespace}|{className}|{string.Join(',', properties)}|{only?.Property}={only?.Value}";
            return _answers.GetOrAdd(question, _ => new(() => inner.Query(wmiNamespace, className, properties, only))).Value;
        }
    }

    private sealed class CachedWindowsUpdateProbe(IWindowsUpdateProbe inner) : IWindowsUpdateProbe
    {
        private readonly Lazy<ProbeResult<WindowsUpdateStatus>> _status = new(inner.GetStatus);

        public ProbeResult<WindowsUpdateStatus> GetStatus() => _status.Value;
    }

    private sealed class CachedPowerProbe(IPowerProbe inner) : IPowerProbe
    {
        private readonly Lazy<ProbeResult<PowerSettings>> _settings = new(inner.GetSettings);

        public ProbeResult<PowerSettings> GetSettings() => _settings.Value;
    }

    private sealed class CachedPlatformProbe(IPlatformProbe inner) : IPlatformProbe
    {
        private readonly Lazy<ProbeResult<FirmwareKind>> _firmware = new(inner.GetFirmware);
        private readonly Lazy<ProbeResult<TpmVersion>> _tpm = new(inner.GetTpm);
        private readonly Lazy<ProbeResult<CodeIntegrityState>> _codeIntegrity = new(inner.GetCodeIntegrity);

        public ProbeResult<FirmwareKind> GetFirmware() => _firmware.Value;

        public ProbeResult<TpmVersion> GetTpm() => _tpm.Value;

        public ProbeResult<CodeIntegrityState> GetCodeIntegrity() => _codeIntegrity.Value;
    }
}
