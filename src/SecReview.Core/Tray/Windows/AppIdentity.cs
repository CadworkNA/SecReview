using System.Runtime.Versioning;
using SecReview.Probing.Windows;
using Windows.Win32;

namespace SecReview.Tray.Windows;

/// <summary>The identity Windows groups SecReview's windows and notifications under.</summary>
[SupportedOSPlatform(MinimumWindows.Platform)]
public static class AppIdentity
{
    /// <summary>
    /// Gives this process the identity setup gave the Start menu shortcut
    /// (<see cref="AppNotification.AppId"/>), so the window joins the shortcut pinned to the
    /// taskbar however it was started. Only for the installed copy: the identity belongs to it.
    /// Changes nothing outside this process.
    /// </summary>
    /// <returns>Whether Windows took it.</returns>
    public static bool UseForThisProcess() => PInvoke.SetCurrentProcessExplicitAppUserModelID(AppNotification.AppId).Succeeded;
}
