using System.Runtime.Versioning;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.System.Com;

namespace SecReview.Probing.Windows;

/// <summary>
/// Makes sure COM is initialised on the calling thread for the duration of a probe. Probes run
/// on worker threads, which have no COM apartment until asked.
/// </summary>
[SupportedOSPlatform(MinimumWindows.Platform)]
internal readonly ref struct ComScope
{
    private readonly bool _uninitialize;

    private ComScope(bool uninitialize) => _uninitialize = uninitialize;

    public static ComScope Enter()
    {
        // S_OK and S_FALSE both need a matching CoUninitialize. RPC_E_CHANGED_MODE means the
        // thread already has a different apartment, which is usable as it is.
        HRESULT result = PInvoke.CoInitializeEx(COINIT.COINIT_MULTITHREADED | COINIT.COINIT_DISABLE_OLE1DDE);
        return new ComScope(result.Succeeded);
    }

    public void Dispose()
    {
        if (_uninitialize)
        {
            PInvoke.CoUninitialize();
        }
    }
}
