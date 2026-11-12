using SecReview.Probing;

namespace SecReview.Checks.BuiltIn;

/// <summary>User Account Control must be on, so programs do not get administrator rights unasked.</summary>
public sealed class UacCheck : ICheck
{
    public const string Id = "system.uac";

    internal const string Key = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    internal const string Value = "EnableLUA";

    private const string Item = "User Account Control";
    private const string Source = @"HKLM\" + Key + @"\" + Value;

    public CheckDefinition Definition { get; } = new(Id, CheckCategory.SystemIntegrity, Severity.High);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (RegistryReader.Number(
                context.Probes.Registry, RegistryRoot.LocalMachine, Key, Value, "the User Account Control setting", out long? enabled)
            is { } failed)
        {
            return failed;
        }

        return enabled switch
        {
            // Windows treats a missing value as on.
            null => CheckOutcome.Pass("User Account Control is on.", Finding.Ok(Item, "On (Windows default)", "On", Source)),
            0 => CheckOutcome.Fail("User Account Control is off.", Finding.Problem(Item, "Off", "On", Source)),
            _ => CheckOutcome.Pass("User Account Control is on.", Finding.Ok(Item, "On", "On", Source)),
        };
    }
}

/// <summary>
/// Secure Boot must be on. A PC that starts in legacy BIOS mode cannot have it. The state comes
/// from the value Windows itself keeps in the registry at start-up.
/// </summary>
public sealed class SecureBootCheck : ICheck
{
    public const string Id = "system.secureboot";

    internal const string Key = @"SYSTEM\CurrentControlSet\Control\SecureBoot\State";
    internal const string Value = "UEFISecureBootEnabled";

    private const string Item = "Secure Boot";
    private const string Source = @"HKLM\" + Key + @"\" + Value;

    public CheckDefinition Definition { get; } = new(Id, CheckCategory.SystemIntegrity, Severity.Medium);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        ProbeResult<FirmwareKind> firmware = context.Probes.Platform.GetFirmware();
        if (!firmware.IsOk)
        {
            return ProbeOutcomes.FromFailure(firmware, "how this PC starts");
        }

        if (firmware.Value == FirmwareKind.Bios)
        {
            return CheckOutcome.Fail(
                "This PC starts in legacy BIOS mode, which has no Secure Boot.",
                Finding.Problem(Item, "Not available (legacy BIOS)", "On"));
        }

        if (RegistryReader.Number(
                context.Probes.Registry, RegistryRoot.LocalMachine, Key, Value, "the Secure Boot state", out long? enabled)
            is { } failed)
        {
            return failed;
        }

        return enabled switch
        {
            null => CheckOutcome.Error("Windows does not report whether Secure Boot is on."),
            0 => CheckOutcome.Fail("Secure Boot is off.", Finding.Problem(Item, "Off", "On", Source)),
            _ => CheckOutcome.Pass("Secure Boot is on.", Finding.Ok(Item, "On", "On", Source)),
        };
    }
}

/// <summary>The PC must have a TPM 2.0 that Windows can use; BitLocker and Windows Hello rely on it.</summary>
public sealed class TpmCheck : ICheck
{
    public const string Id = "system.tpm";

    private const string Item = "Security chip (TPM)";
    private const string Expected = "TPM 2.0";

    public CheckDefinition Definition { get; } = new(Id, CheckCategory.SystemIntegrity, Severity.Medium);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        ProbeResult<TpmVersion> tpm = context.Probes.Platform.GetTpm();
        if (!tpm.IsOk)
        {
            return ProbeOutcomes.FromFailure(tpm, "the TPM");
        }

        return tpm.Value switch
        {
            TpmVersion.Version20 => CheckOutcome.Pass("This PC has a TPM 2.0.", Finding.Ok(Item, "TPM 2.0", Expected)),
            TpmVersion.Version12 => CheckOutcome.Fail(
                "This PC has an older TPM 1.2.", Finding.Problem(Item, "TPM 1.2", Expected)),
            _ => CheckOutcome.Fail(
                "Windows finds no TPM; it may be switched off in the firmware.", Finding.Problem(Item, "None found", Expected)),
        };
    }
}

/// <summary>Memory integrity must be running, so drivers cannot be used to tamper with Windows itself.</summary>
public sealed class MemoryIntegrityCheck : ICheck
{
    public const string Id = "system.memoryintegrity";

    private const string Item = "Memory integrity";

    public CheckDefinition Definition { get; } = new(Id, CheckCategory.SystemIntegrity, Severity.Medium);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        ProbeResult<CodeIntegrityState> state = context.Probes.Platform.GetCodeIntegrity();
        if (!state.IsOk)
        {
            return ProbeOutcomes.FromFailure(state, "whether memory integrity is running");
        }

        return state.Value!.MemoryIntegrity
            ? CheckOutcome.Pass("Memory integrity is running.", Finding.Ok(Item, "Running", "Running"))
            : CheckOutcome.Fail("Memory integrity is not running.", Finding.Problem(Item, "Not running", "Running"));
    }
}

/// <summary>
/// Windows must not be started in a developer mode that weakens it: accepting test-signed
/// drivers, or with kernel debugging on.
/// </summary>
public sealed class BootOptionsCheck : ICheck
{
    public const string Id = "system.bootoptions";

    public CheckDefinition Definition { get; } = new(Id, CheckCategory.SystemIntegrity, Severity.Medium);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        ProbeResult<CodeIntegrityState> read = context.Probes.Platform.GetCodeIntegrity();
        if (!read.IsOk)
        {
            return ProbeOutcomes.FromFailure(read, "how Windows was started");
        }

        CodeIntegrityState state = read.Value!;
        List<Finding> findings =
        [
            state.TestSigning
                ? Finding.Problem("Test-signed drivers", "Accepted", "Refused")
                : Finding.Ok("Test-signed drivers", "Refused", "Refused"),
            state.KernelDebugging
                ? Finding.Problem("Kernel debugging", "On", "Off")
                : Finding.Ok("Kernel debugging", "Off", "Off"),
        ];

        return (state.TestSigning, state.KernelDebugging) switch
        {
            (true, true) => CheckOutcome.Fail("Windows accepts test-signed drivers and kernel debugging is on.", findings),
            (true, false) => CheckOutcome.Fail("Windows accepts test-signed drivers.", findings),
            (false, true) => CheckOutcome.Fail("Kernel debugging is on.", findings),
            _ => CheckOutcome.Pass("Windows was started with its normal protections.", findings),
        };
    }
}
