using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using SecReview.Probing.Windows;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.Graphics.Gdi;
using Windows.Win32.UI.Shell;
using Windows.Win32.UI.WindowsAndMessaging;

namespace SecReview.Tray.Windows;

/// <summary>
/// SecReview's icon in the notification area: the icon itself, its tooltip, its menu and the
/// notification it can show. Plain Windows calls and a hidden window to receive what the icon
/// reports; no XAML, so the process behind the icon stays small.
/// </summary>
/// <remarks>
/// Everything here runs on the thread that calls <see cref="Run"/>; other threads use
/// <see cref="Post"/>. One icon per process.
/// </remarks>
[SupportedOSPlatform(MinimumWindows.Platform)]
public sealed unsafe class NotificationAreaIcon : ITrayIcon, IDisposable
{
    private const uint IconId = 1;
    private const uint CallbackMessage = PInvoke.WM_APP + 1;
    private const uint PostedMessage = PInvoke.WM_APP + 2;
    private const nuint TimerId = 1;

    // Menu commands. Zero means "nothing chosen".
    private const uint MenuOpen = 1;
    private const uint MenuCheckNow = 2;
    private const uint MenuPauseHour = 3;
    private const uint MenuPauseDay = 4;
    private const uint MenuResume = 5;
    private const uint MenuQuit = 6;

    private static NotificationAreaIcon? s_current;

    private readonly Action<TrayCommand> _onCommand;
    private readonly ConcurrentQueue<Action> _posted = new();
    private readonly uint _taskbarCreated;
    private HWND _window;
    private HICON _icon;
    private bool _added;
    private bool _paused;
    private bool _busy;
    private string _tooltip = "SecReview";

    /// <param name="onCommand">Called on the icon's thread for every command.</param>
    /// <exception cref="InvalidOperationException">The hidden window could not be made, or there is an icon already.</exception>
    public NotificationAreaIcon(Action<TrayCommand> onCommand)
    {
        ArgumentNullException.ThrowIfNull(onCommand);
        _onCommand = onCommand;
        if (Interlocked.CompareExchange(ref s_current, this, null) is not null)
        {
            throw new InvalidOperationException("There is one notification-area icon per process.");
        }

        fixed (char* className = "SecReview.NotificationArea")
        fixed (char* taskbarCreated = "TaskbarCreated")
        {
            HINSTANCE module = new(PInvoke.GetModuleHandle((PCWSTR)null).Value);
            var windowClass = new WNDCLASSEXW
            {
                cbSize = (uint)sizeof(WNDCLASSEXW),
                lpfnWndProc = &WindowProcedure,
                hInstance = module,
                lpszClassName = className,
            };
            if (PInvoke.RegisterClassEx(&windowClass) == 0)
            {
                s_current = null;
                throw new InvalidOperationException($"The icon's window class could not be registered ({Marshal.GetLastPInvokeError()}).");
            }

            // An ordinary window that is never shown. Not a "message-only" one: those do not
            // get the message Windows sends when the taskbar has been restarted.
            _window = PInvoke.CreateWindowEx(0, className, className, 0, 0, 0, 0, 0, HWND.Null, HMENU.Null, module, null);
            if (_window.IsNull)
            {
                s_current = null;
                throw new InvalidOperationException($"The icon's window could not be made ({Marshal.GetLastPInvokeError()}).");
            }

            _taskbarCreated = PInvoke.RegisterWindowMessage(taskbarCreated);
        }
    }

    /// <summary>Whether Windows took the icon. False where there is no notification area (no taskbar running).</summary>
    public bool IsShown => _added;

    /// <summary>Shows the icon in a state, with a tooltip and the menu that goes with it.</summary>
    public void Update(TrayState state, bool darkTaskbar, string tooltip, bool paused, bool busy)
    {
        ArgumentNullException.ThrowIfNull(tooltip);
        _tooltip = tooltip;
        _paused = paused;
        _busy = busy;

        HICON previous = _icon;
        _icon = CreateIcon(state, darkTaskbar);
        ShowIcon();
        if (!previous.IsNull)
        {
            PInvoke.DestroyIcon(previous);
        }
    }

    /// <summary>Shows a notification next to the icon. Nothing happens when the icon is not shown.</summary>
    public void Notify(string title, string text)
    {
        ArgumentNullException.ThrowIfNull(title);
        ArgumentNullException.ThrowIfNull(text);
        if (!_added)
        {
            return;
        }

        NOTIFYICONDATAW data = NewData();
        data.uFlags = NOTIFY_ICON_DATA_FLAGS.NIF_INFO;
        data.dwInfoFlags = NOTIFY_ICON_INFOTIP_FLAGS.NIIF_WARNING;
        Copy(title, data.szInfoTitle.AsSpan());
        Copy(text, data.szInfo.AsSpan());
        PInvoke.Shell_NotifyIcon(NOTIFY_ICON_MESSAGE.NIM_MODIFY, &data);
    }

    /// <summary>Has the icon's thread report <see cref="TrayCommand.Tick"/> at this interval.</summary>
    public void StartTimer(TimeSpan interval) =>
        PInvoke.SetTimer(_window, TimerId, (uint)Math.Clamp(interval.TotalMilliseconds, 1000, int.MaxValue), null);

    /// <summary>Runs an action on the icon's thread. Safe to call from any thread.</summary>
    public void Post(Action action)
    {
        ArgumentNullException.ThrowIfNull(action);
        _posted.Enqueue(action);
        PInvoke.PostMessage(_window, PostedMessage, 0, 0);
    }

    /// <summary>Handles the icon until <see cref="Quit"/>. Returns when the icon is gone.</summary>
    public void Run()
    {
        ObjectDisposedException.ThrowIf(_window.IsNull, this);

        MSG message;
        while (PInvoke.GetMessage(&message, HWND.Null, 0, 0) > 0)
        {
            PInvoke.TranslateMessage(&message);
            PInvoke.DispatchMessage(&message);
        }
    }

    /// <summary>Removes the icon and ends <see cref="Run"/>. Safe to call from any thread.</summary>
    public void Quit() => Post(() => PInvoke.DestroyWindow(_window));

    public void Dispose()
    {
        RemoveIcon();
        if (!_icon.IsNull)
        {
            PInvoke.DestroyIcon(_icon);
            _icon = HICON.Null;
        }

        if (!_window.IsNull)
        {
            PInvoke.DestroyWindow(_window);
            _window = HWND.Null;
        }

        Interlocked.CompareExchange(ref s_current, null, this);
    }

    /// <summary>Adds the icon, or changes it when it is there already.</summary>
    private void ShowIcon()
    {
        NOTIFYICONDATAW data = NewData();
        data.uFlags = NOTIFY_ICON_DATA_FLAGS.NIF_MESSAGE | NOTIFY_ICON_DATA_FLAGS.NIF_ICON | NOTIFY_ICON_DATA_FLAGS.NIF_TIP | NOTIFY_ICON_DATA_FLAGS.NIF_SHOWTIP;
        data.uCallbackMessage = CallbackMessage;
        data.hIcon = _icon;
        Copy(_tooltip, data.szTip.AsSpan());

        if (_added)
        {
            PInvoke.Shell_NotifyIcon(NOTIFY_ICON_MESSAGE.NIM_MODIFY, &data);
            return;
        }

        if (PInvoke.Shell_NotifyIcon(NOTIFY_ICON_MESSAGE.NIM_ADD, &data))
        {
            // The current way of reporting clicks (where on screen, keyboard or mouse).
            data.Anonymous.uVersion = PInvoke.NOTIFYICON_VERSION_4;
            PInvoke.Shell_NotifyIcon(NOTIFY_ICON_MESSAGE.NIM_SETVERSION, &data);
            _added = true;
        }
    }

    private void RemoveIcon()
    {
        if (_added)
        {
            NOTIFYICONDATAW data = NewData();
            PInvoke.Shell_NotifyIcon(NOTIFY_ICON_MESSAGE.NIM_DELETE, &data);
            _added = false;
        }
    }

    private NOTIFYICONDATAW NewData() => new()
    {
        cbSize = (uint)sizeof(NOTIFYICONDATAW),
        hWnd = _window,
        uID = IconId,
    };

    /// <summary>Copies a text into one of the fixed-size fields, cut to fit and ended with a zero.</summary>
    private static void Copy(string text, Span<char> field)
    {
        field.Clear();
        text.AsSpan(0, Math.Min(text.Length, field.Length - 1)).CopyTo(field);
    }

    /// <summary>The icon's picture as something Windows can show, at the size the notification area uses.</summary>
    private static HICON CreateIcon(TrayState state, bool darkTaskbar)
    {
        int size = Math.Clamp(PInvoke.GetSystemMetrics(SYSTEM_METRICS_INDEX.SM_CXSMICON), 16, 64);
        byte[] pixels = TrayIconImage.Draw(size, state, darkTaskbar);

        var header = new BITMAPINFO();
        header.bmiHeader.biSize = (uint)sizeof(BITMAPINFOHEADER);
        header.bmiHeader.biWidth = size;
        header.bmiHeader.biHeight = -size; // rows from the top, as the picture is drawn
        header.bmiHeader.biPlanes = 1;
        header.bmiHeader.biBitCount = 32;

        void* bits;
        HBITMAP colour = PInvoke.CreateDIBSection(HDC.Null, &header, DIB_USAGE.DIB_RGB_COLORS, &bits, HANDLE.Null, 0);
        if (colour.IsNull || bits is null)
        {
            return HICON.Null;
        }

        pixels.AsSpan().CopyTo(new Span<byte>(bits, pixels.Length));

        // The mask is all zeros: the picture's own alpha says what is see-through.
        HBITMAP mask = PInvoke.CreateBitmap(size, size, 1, 1, null);
        try
        {
            var info = new ICONINFO { fIcon = true, hbmMask = mask, hbmColor = colour };
            return PInvoke.CreateIconIndirect(&info);
        }
        finally
        {
            PInvoke.DeleteObject(new HGDIOBJ(colour.Value));
            if (!mask.IsNull)
            {
                PInvoke.DeleteObject(new HGDIOBJ(mask.Value));
            }
        }
    }

    /// <param name="x">Where the icon was clicked, or where it is when the keyboard asked.</param>
    /// <param name="y">The same, down the screen.</param>
    private void ShowMenu(int x, int y)
    {
        HMENU menu = PInvoke.CreatePopupMenu();
        if (menu.IsNull)
        {
            return;
        }

        try
        {
            Add(menu, MenuOpen, "Open SecReview", enabled: true);
            Add(menu, MenuCheckNow, _busy ? "Checking…" : "Check now", enabled: !_busy);
            PInvoke.AppendMenu(menu, MENU_ITEM_FLAGS.MF_SEPARATOR, 0, (PCWSTR)null);
            if (_paused)
            {
                Add(menu, MenuResume, "Resume checking", enabled: true);
            }
            else
            {
                Add(menu, MenuPauseHour, "Pause for 1 hour", enabled: true);
                Add(menu, MenuPauseDay, "Pause for 1 day", enabled: true);
            }

            PInvoke.AppendMenu(menu, MENU_ITEM_FLAGS.MF_SEPARATOR, 0, (PCWSTR)null);
            Add(menu, MenuQuit, "Quit", enabled: true);

            // Windows only closes a menu on a click elsewhere when its window is in front.
            PInvoke.SetForegroundWindow(_window);
            uint chosen = (uint)PInvoke.TrackPopupMenuEx(
                menu,
                (uint)(TRACK_POPUP_MENU_FLAGS.TPM_RETURNCMD | TRACK_POPUP_MENU_FLAGS.TPM_NONOTIFY | TRACK_POPUP_MENU_FLAGS.TPM_RIGHTBUTTON | TRACK_POPUP_MENU_FLAGS.TPM_BOTTOMALIGN),
                x,
                y,
                _window,
                null).Value;
            PInvoke.PostMessage(_window, PInvoke.WM_NULL, 0, 0);

            TrayCommand? command = chosen switch
            {
                MenuOpen => TrayCommand.Open,
                MenuCheckNow => TrayCommand.CheckNow,
                MenuPauseHour => TrayCommand.PauseHour,
                MenuPauseDay => TrayCommand.PauseDay,
                MenuResume => TrayCommand.Resume,
                MenuQuit => TrayCommand.Quit,
                _ => null,
            };
            if (command is { } picked)
            {
                _onCommand(picked);
            }
        }
        finally
        {
            PInvoke.DestroyMenu(menu);
        }

        static void Add(HMENU menu, uint id, string text, bool enabled)
        {
            fixed (char* label = text)
            {
                PInvoke.AppendMenu(menu, MENU_ITEM_FLAGS.MF_STRING | (enabled ? MENU_ITEM_FLAGS.MF_ENABLED : MENU_ITEM_FLAGS.MF_GRAYED), id, label);
            }
        }
    }

    private LRESULT Handle(HWND window, uint message, WPARAM wParam, LPARAM lParam)
    {
        switch (message)
        {
            case CallbackMessage:
                // With version 4 the low word of lParam says what happened to the icon.
                switch ((uint)(lParam.Value & 0xFFFF))
                {
                    case PInvoke.WM_CONTEXTMENU:
                        // With version 4, wParam carries the place on screen (two signed 16-bit numbers).
                        ShowMenu((short)(wParam.Value & 0xFFFF), (short)((wParam.Value >> 16) & 0xFFFF));
                        break;
                    case PInvoke.NIN_SELECT or PInvoke.NIN_SELECT + 1: // a click, or Enter from the keyboard
                        _onCommand(TrayCommand.Open);
                        break;
                    case PInvoke.NIN_BALLOONUSERCLICK:
                        _onCommand(TrayCommand.NotificationClicked);
                        break;
                }

                return new LRESULT(0);

            case PostedMessage:
                while (_posted.TryDequeue(out Action? action))
                {
                    action();
                }

                return new LRESULT(0);

            case PInvoke.WM_TIMER when wParam.Value == TimerId:
                _onCommand(TrayCommand.Tick);
                return new LRESULT(0);

            case PInvoke.WM_DESTROY:
                RemoveIcon();
                PInvoke.KillTimer(window, TimerId);
                _window = HWND.Null;
                PInvoke.PostQuitMessage(0);
                return new LRESULT(0);
        }

        // The taskbar was restarted (Explorer crashed, or started late): the icon is gone and is put back.
        if (message == _taskbarCreated && _taskbarCreated != 0)
        {
            _added = false;
            if (!_icon.IsNull)
            {
                ShowIcon();
            }

            return new LRESULT(0);
        }

        return PInvoke.DefWindowProc(window, message, wParam, lParam);
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static LRESULT WindowProcedure(HWND window, uint message, WPARAM wParam, LPARAM lParam)
    {
        try
        {
            return s_current is { } icon ? icon.Handle(window, message, wParam, lParam) : PInvoke.DefWindowProc(window, message, wParam, lParam);
        }
#pragma warning disable CA1031 // Nothing may be thrown back into Windows; the command's own handler logs what went wrong.
        catch (Exception)
#pragma warning restore CA1031
        {
            return new LRESULT(0);
        }
    }
}
