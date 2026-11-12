using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Windows.Win32;
using Windows.Win32.System.Services;

namespace SecReview.Probing.Windows;

/// <summary>Asks the Service Control Manager how a service is configured and whether it runs.</summary>
[SupportedOSPlatform(MinimumWindows.Platform)]
internal sealed class WindowsServiceProbe : IServiceProbe
{
    private const string What = "Asking the Service Control Manager";
    private const int ErrorServiceDoesNotExist = 1060;
    private const int ErrorInsufficientBuffer = 122;

    public unsafe ProbeResult<ServiceInfo> GetService(string name)
    {
        SC_HANDLE manager = default;
        SC_HANDLE service = default;
        try
        {
            manager = PInvoke.OpenSCManager(null, null, PInvoke.SC_MANAGER_CONNECT);
            if (manager.IsNull)
            {
                return WindowsError.FromWin32(Marshal.GetLastPInvokeError(), What);
            }

            service = PInvoke.OpenService(
                manager, name, PInvoke.SERVICE_QUERY_CONFIG | PInvoke.SERVICE_QUERY_STATUS);
            if (service.IsNull)
            {
                int error = Marshal.GetLastPInvokeError();
                return error == ErrorServiceDoesNotExist
                    ? ProbeFailure.NotFound()
                    : WindowsError.FromWin32(error, What);
            }

            // First call asks for the size, second fills the buffer.
            if (PInvoke.QueryServiceConfig(service, null, 0, out uint needed))
            {
                return ProbeFailure.Failed($"{What} failed: unexpected empty configuration.");
            }

            int sizeError = Marshal.GetLastPInvokeError();
            if (sizeError != ErrorInsufficientBuffer)
            {
                return WindowsError.FromWin32(sizeError, What);
            }

            byte[] buffer = new byte[needed];
            SERVICE_START_TYPE startType;
            fixed (byte* pointer = buffer)
            {
                var config = (QUERY_SERVICE_CONFIGW*)pointer;
                if (!PInvoke.QueryServiceConfig(service, config, needed, out _))
                {
                    return WindowsError.FromWin32(Marshal.GetLastPInvokeError(), What);
                }

                startType = config->dwStartType;
            }

            if (!PInvoke.QueryServiceStatus(service, out SERVICE_STATUS status))
            {
                return WindowsError.FromWin32(Marshal.GetLastPInvokeError(), What);
            }

            return ProbeResult<ServiceInfo>.Ok(new ServiceInfo(
                name,
                ToStartType(startType),
                IsRunning: status.dwCurrentState != SERVICE_STATUS_CURRENT_STATE.SERVICE_STOPPED));
        }
        catch (Exception exception)
        {
            return WindowsError.FromException(exception, What);
        }
        finally
        {
            if (!service.IsNull)
            {
                PInvoke.CloseServiceHandle(service);
            }

            if (!manager.IsNull)
            {
                PInvoke.CloseServiceHandle(manager);
            }
        }
    }

    private static ServiceStartType ToStartType(SERVICE_START_TYPE type) => type switch
    {
        SERVICE_START_TYPE.SERVICE_DISABLED => ServiceStartType.Disabled,
        SERVICE_START_TYPE.SERVICE_DEMAND_START => ServiceStartType.Manual,
        _ => ServiceStartType.Automatic,
    };
}
