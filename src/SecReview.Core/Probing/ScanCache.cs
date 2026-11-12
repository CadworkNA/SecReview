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
        };
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
