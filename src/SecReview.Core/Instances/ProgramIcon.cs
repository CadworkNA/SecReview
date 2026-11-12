using System.Runtime.Versioning;
using SecReview.Probing.Windows;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.UI.WindowsAndMessaging;

namespace SecReview.Instances;

/// <summary>The icon compiled into the running program, put on one of its windows.</summary>
[SupportedOSPlatform(MinimumWindows.Platform)]
public static unsafe class ProgramIcon
{
    /// <summary>The resource number the .NET tools give a program's icon.</summary>
    private const int IconResource = 32512;

    private const nuint SmallIcon = 0;
    private const nuint BigIcon = 1;

    /// <summary>
    /// Gives a window the program's icon, small for the title bar and big for the taskbar and
    /// Alt+Tab. False when the program has no icon (a build without the icon file).
    /// </summary>
    public static bool Apply(nint window)
    {
        var handle = new HWND(window);
        HINSTANCE module = new(PInvoke.GetModuleHandle((PCWSTR)null).Value);
        bool any = false;
        foreach ((nuint which, SYSTEM_METRICS_INDEX width, SYSTEM_METRICS_INDEX height) in new[]
        {
            (SmallIcon, SYSTEM_METRICS_INDEX.SM_CXSMICON, SYSTEM_METRICS_INDEX.SM_CYSMICON),
            (BigIcon, SYSTEM_METRICS_INDEX.SM_CXICON, SYSTEM_METRICS_INDEX.SM_CYICON),
        })
        {
            // Shared: Windows keeps the icon for the life of the program, so there is nothing to free.
            HANDLE icon = PInvoke.LoadImage(
                module,
                (PCWSTR)(char*)IconResource,
                GDI_IMAGE_TYPE.IMAGE_ICON,
                PInvoke.GetSystemMetrics(width),
                PInvoke.GetSystemMetrics(height),
                IMAGE_FLAGS.LR_SHARED);
            if (!icon.IsNull)
            {
                PInvoke.SendMessage(handle, PInvoke.WM_SETICON, which, (nint)icon.Value);
                any = true;
            }
        }

        return any;
    }
}
