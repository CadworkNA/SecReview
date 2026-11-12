using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Windows.Win32;
using Windows.Win32.System.SystemInformation;
using Windows.Win32.System.TpmBaseServices;

namespace SecReview.Probing.Windows;

/// <summary>Firmware type, TPM and code-integrity state, from documented Windows calls.</summary>
[SupportedOSPlatform(MinimumWindows.Platform)]
internal sealed partial class WindowsPlatformProbe : IPlatformProbe
{
    /// <summary>TBS_E_TPM_NOT_FOUND: "A compatible TPM Security Device cannot be found on this computer".</summary>
    private const uint TpmNotFound = 0x8028400F;

    /// <summary>TBS_E_SERVICE_DISABLED / TBS_E_SERVICE_NOT_RUNNING / TBS_E_DEACTIVATED: there is no usable TPM.</summary>
    private const uint TbsServiceDisabled = 0x80284010;
    private const uint TbsServiceNotRunning = 0x80284008;
    private const uint TbsDeactivated = 0x80284016;

    // TPM_DEVICE_INFO.tpmVersion values (tbs.h).
    private const uint TpmVersion12 = 1;
    private const uint TpmVersion20 = 2;

    // NtQuerySystemInformation's SystemCodeIntegrityInformation and the documented option bits.
    private const int SystemCodeIntegrityInformation = 103;
    private const uint OptionTestSign = 0x02;
    private const uint OptionDebugModeEnabled = 0x80;
    private const uint OptionHvciKernelModeEnabled = 0x400;

    public unsafe ProbeResult<FirmwareKind> GetFirmware()
    {
        const string What = "Asking how the PC starts";
        try
        {
            FIRMWARE_TYPE type;
            if (!PInvoke.GetFirmwareType(&type))
            {
                return WindowsError.FromWin32(Marshal.GetLastPInvokeError(), What);
            }

            return ProbeResult<FirmwareKind>.Ok(type switch
            {
                FIRMWARE_TYPE.FirmwareTypeBios => FirmwareKind.Bios,
                FIRMWARE_TYPE.FirmwareTypeUefi => FirmwareKind.Uefi,
                _ => FirmwareKind.Unknown,
            });
        }
        catch (Exception exception)
        {
            return WindowsError.FromException(exception, What);
        }
    }

    public unsafe ProbeResult<TpmVersion> GetTpm()
    {
        const string What = "Asking for the TPM";
        try
        {
            TPM_DEVICE_INFO info;
            uint result = PInvoke.Tbsi_GetDeviceInfo((uint)sizeof(TPM_DEVICE_INFO), &info);
            if (result is TpmNotFound or TbsServiceDisabled or TbsServiceNotRunning or TbsDeactivated)
            {
                return ProbeResult<TpmVersion>.Ok(TpmVersion.None);
            }

            if (result != 0)
            {
                return WindowsError.FromHResult(unchecked((int)result), What);
            }

            return info.tpmVersion switch
            {
                TpmVersion12 => ProbeResult<TpmVersion>.Ok(TpmVersion.Version12),
                TpmVersion20 => ProbeResult<TpmVersion>.Ok(TpmVersion.Version20),
                _ => ProbeFailure.Failed($"{What} gave an unknown TPM version ({info.tpmVersion})."),
            };
        }
        catch (Exception exception)
        {
            return WindowsError.FromException(exception, What);
        }
    }

    public ProbeResult<CodeIntegrityState> GetCodeIntegrity()
    {
        const string What = "Asking how Windows checks drivers";
        try
        {
            var info = new CodeIntegrityInformation { Length = (uint)Marshal.SizeOf<CodeIntegrityInformation>() };
            int status = NtQuerySystemInformation(SystemCodeIntegrityInformation, ref info, info.Length, out _);
            if (status != 0)
            {
                return ProbeFailure.Failed($"{What} failed (0x{status:X8}).");
            }

            uint options = info.CodeIntegrityOptions;
            return ProbeResult<CodeIntegrityState>.Ok(new CodeIntegrityState(
                TestSigning: (options & OptionTestSign) != 0,
                KernelDebugging: (options & OptionDebugModeEnabled) != 0,
                MemoryIntegrity: (options & OptionHvciKernelModeEnabled) != 0));
        }
        catch (Exception exception)
        {
            return WindowsError.FromException(exception, What);
        }
    }

    // Declared by hand: the generated declarations do not include this function.
    [LibraryImport("ntdll.dll")]
    private static partial int NtQuerySystemInformation(
        int systemInformationClass, ref CodeIntegrityInformation systemInformation, uint length, out uint returnLength);

    /// <summary>SYSTEM_CODEINTEGRITY_INFORMATION.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct CodeIntegrityInformation
    {
        public uint Length;
        public uint CodeIntegrityOptions;
    }
}
