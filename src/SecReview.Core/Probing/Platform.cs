namespace SecReview.Probing;

/// <summary>How the PC starts.</summary>
public enum FirmwareKind
{
    /// <summary>Windows did not say.</summary>
    Unknown = 0,

    /// <summary>Legacy BIOS; Secure Boot is not possible.</summary>
    Bios,

    Uefi,
}

/// <summary>The security chip Windows can use.</summary>
public enum TpmVersion
{
    /// <summary>No TPM that Windows can use: none fitted, or switched off in the firmware.</summary>
    None = 0,

    /// <summary>TPM 1.2.</summary>
    Version12,

    /// <summary>TPM 2.0.</summary>
    Version20,
}

/// <summary>What Windows reports about how it checks the code it loads.</summary>
/// <param name="TestSigning">Test-signed drivers are accepted.</param>
/// <param name="KernelDebugging">Kernel debugging is switched on.</param>
/// <param name="MemoryIntegrity">Memory integrity (hypervisor-protected code integrity) is running.</param>
public sealed record CodeIntegrityState(bool TestSigning, bool KernelDebugging, bool MemoryIntegrity);

/// <summary>Reads hardware-backed protections. None of these needs administrator rights.</summary>
public interface IPlatformProbe
{
    ProbeResult<FirmwareKind> GetFirmware();

    ProbeResult<TpmVersion> GetTpm();

    ProbeResult<CodeIntegrityState> GetCodeIntegrity();
}
