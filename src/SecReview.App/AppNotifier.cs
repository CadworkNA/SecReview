using SecReview.Diagnostics;
using SecReview.Tray;
using Windows.Data.Xml.Dom;
using Windows.UI.Notifications;

namespace SecReview.App;

/// <summary>
/// Windows' side of SecReview's app notifications (<see cref="AppNotification"/>): they stay
/// in the notification centre, and a click opens the window through setup's registration.
/// </summary>
internal sealed class AppNotifier
{
    /// <summary>"Element not found": Windows knows no app by that identity, so setup's registration is missing.</summary>
    private const int NotRegistered = unchecked((int)0x80070490);

    private readonly AppLog _log;

    public AppNotifier(AppLog log) => _log = log;

    /// <summary>Shows the notification. Never throws: what Windows refuses is logged and says "unavailable".</summary>
    public AppNotificationOutcome Show(TrayNotification notification)
    {
        try
        {
            ToastNotifier notifier = ToastNotificationManager.CreateToastNotifier(AppNotification.AppId);

            // Reading the setting is also what fails when Windows does not know SecReview.
            NotificationSetting setting = notifier.Setting;
            switch (setting)
            {
                case NotificationSetting.Enabled:
                    break;
                case NotificationSetting.DisabledForApplication or NotificationSetting.DisabledForUser or NotificationSetting.DisabledByGroupPolicy:
                    _log.Info($"A notification was not shown: notifications are switched off in Windows ({setting}).");
                    return AppNotificationOutcome.SwitchedOff;
                default:
                    _log.Info($"Windows does not take app notifications from SecReview ({setting}); the icon shows its own.");
                    return AppNotificationOutcome.Unavailable;
            }

            var content = new XmlDocument();
            content.LoadXml(AppNotification.Xml(notification));
            notifier.Show(new ToastNotification(content));
            return AppNotificationOutcome.Shown;
        }
#pragma warning disable CA1031 // Whatever Windows refuses, the icon's own notification is shown instead; the reason is logged.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            if (exception.HResult == NotRegistered)
            {
                _log.Info("Windows does not know SecReview's notifications (setup's registration is missing); the icon shows its own.");
            }
            else
            {
                _log.Error("An app notification could not be shown; the icon shows its own", exception);
            }

            return AppNotificationOutcome.Unavailable;
        }
    }
}
