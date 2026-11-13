using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Xml;
using SecReview.Diagnostics;

namespace SecReview.Tray;

/// <summary>A notification about checks that started failing.</summary>
/// <param name="Title">The check's title, or how many started failing.</param>
/// <param name="Text">The check's reason, or the titles of the first few.</param>
/// <param name="CheckId">The check to open the window on; null when several started failing.</param>
public sealed record TrayNotification(string Title, string Text, string? CheckId);

/// <summary>What became of an app notification.</summary>
public enum AppNotificationOutcome
{
    /// <summary>
    /// It could not be shown: this copy is not the installed one, runs with administrator
    /// rights, or setup's registration is missing. The icon's own notification is used instead.
    /// </summary>
    Unavailable = 0,

    /// <summary>Windows shows it.</summary>
    Shown,

    /// <summary>
    /// SecReview's notifications, or all of them, are switched off in Windows (by the user or
    /// the organisation). Nothing is shown: the icon's own would go around that choice.
    /// </summary>
    SwitchedOff,
}

/// <summary>
/// SecReview's registered app notifications: what setup registers for them, what one holds,
/// and what a click on one may ask for. Windows' side is <c>AppNotifier</c> in the app and
/// <c>NotificationClicks</c>.
/// </summary>
/// <remarks>
/// Setup gives the Start menu shortcut <see cref="AppId"/> and <see cref="ActivatorId"/>, and
/// registers <see cref="ActivatorId"/> to start <c>SecReview.exe</c> with
/// <see cref="CommandLine.AppArguments.NotificationClickSwitch"/>. The app writes nothing.
/// </remarks>
public static class AppNotification
{
    /// <summary>The application identity Windows files SecReview's notifications under. Never change it.</summary>
    public const string AppId = "Cadwork.SecReview";

    /// <summary>The COM class Windows starts SecReview through when a notification is clicked. Never change it.</summary>
    public static readonly Guid ActivatorId = new("164B92DB-C7E7-4DDB-B345-C9BFAD05817F");

    /// <summary>The folder setup installs into, under Program Files.</summary>
    public const string InstallFolderName = "SecReview";

    /// <summary>What a click asks for: open the window.</summary>
    private const string ShowArgument = "show";

    /// <summary>Longer arguments are not SecReview's.</summary>
    private const int MaximumArgumentsLength = 200;

    /// <summary>
    /// Whether this copy is the one setup installed, which is the one its registration starts.
    /// A copy anywhere else keeps to the icon's own notification.
    /// </summary>
    /// <param name="appDirectory">The folder the app runs from.</param>
    /// <param name="programFiles">The Program Files folder.</param>
    public static bool IsInstalledCopy(string appDirectory, string? programFiles)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(appDirectory);
        if (string.IsNullOrWhiteSpace(programFiles))
        {
            return false;
        }

        try
        {
            return string.Equals(
                Path.GetFullPath(appDirectory).TrimEnd('\\'),
                Path.Combine(Path.GetFullPath(programFiles).TrimEnd('\\'), InstallFolderName),
                StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    /// <summary>
    /// The notification as Windows takes it: the title, the reason and a "Show" button. A click
    /// on the notification or the button opens the window, on the check when there is one.
    /// </summary>
    public static string Xml(TrayNotification notification)
    {
        ArgumentNullException.ThrowIfNull(notification);
        string arguments = Arguments(notification.CheckId);

        var text = new StringBuilder();
        using (XmlWriter writer = XmlWriter.Create(text, new XmlWriterSettings { OmitXmlDeclaration = true }))
        {
            writer.WriteStartElement("toast");
            writer.WriteAttributeString("launch", arguments);
            writer.WriteAttributeString("activationType", "foreground");

            writer.WriteStartElement("visual");
            writer.WriteStartElement("binding");
            writer.WriteAttributeString("template", "ToastGeneric");
            writer.WriteElementString("text", XmlText(notification.Title));
            writer.WriteElementString("text", XmlText(notification.Text));
            writer.WriteEndElement();
            writer.WriteEndElement();

            writer.WriteStartElement("actions");
            writer.WriteStartElement("action");
            writer.WriteAttributeString("content", "Show");
            writer.WriteAttributeString("arguments", arguments);
            writer.WriteAttributeString("activationType", "foreground");
            writer.WriteEndElement();
            writer.WriteEndElement();

            writer.WriteEndElement();
        }

        return text.ToString();
    }

    /// <summary>
    /// Reads what a click on a notification asks for. Only what <see cref="Xml"/> writes is
    /// taken: "show", or "show:" and a check's identifier. Anything else is refused, since any
    /// program of the user can make Windows deliver a "click".
    /// </summary>
    /// <param name="arguments">The arguments Windows handed over.</param>
    /// <param name="checkId">The check to open the window on; null for the window as it is.</param>
    /// <returns>False when the arguments are not SecReview's: nothing is opened.</returns>
    public static bool TryReadArguments(string? arguments, out string? checkId)
    {
        checkId = null;
        if (arguments is null || arguments.Length > MaximumArgumentsLength)
        {
            return false;
        }

        if (arguments == ShowArgument)
        {
            return true;
        }

        if (arguments.StartsWith(ShowArgument + ":", StringComparison.Ordinal) && arguments[(ShowArgument.Length + 1)..] is var id && IsShowable(id))
        {
            checkId = id;
            return true;
        }

        return false;
    }

    private static string Arguments(string? checkId) => IsShowable(checkId) ? $"{ShowArgument}:{checkId}" : ShowArgument;

    // An identifier never starts with a dash, as on the command line (--show).
    private static bool IsShowable([NotNullWhen(true)] string? checkId) => ErrorReports.IsCheckId(checkId) && checkId[0] != '-';

    /// <summary>The text without characters XML cannot hold (Windows would refuse the whole notification).</summary>
    private static string XmlText(string text)
    {
        var kept = new StringBuilder(text.Length);
        for (int index = 0; index < text.Length; index++)
        {
            char c = text[index];
            if (char.IsHighSurrogate(c) && index + 1 < text.Length && char.IsLowSurrogate(text[index + 1]))
            {
                kept.Append(c).Append(text[++index]);
            }
            else if (XmlConvert.IsXmlChar(c))
            {
                kept.Append(c);
            }
        }

        return kept.ToString();
    }
}
