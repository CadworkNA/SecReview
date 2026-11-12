using System.IO.MemoryMappedFiles;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using SecReview.Diagnostics;
using SecReview.Probing.Windows;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.UI.WindowsAndMessaging;

namespace SecReview.Instances;

/// <summary>
/// The names by which SecReview's processes find each other: one window and one
/// notification-area icon per signed-in user and data folder. The names are local to the
/// user's Windows session, and carry the data folder so a copy run with another folder
/// (a test, a portable copy) is a set of its own.
/// </summary>
public static class InstanceNames
{
    /// <summary>Held by the process behind the notification-area icon.</summary>
    public static string Tray(string dataFolder) => Name("Tray", dataFolder);

    /// <summary>Signalled by the window when it changed the settings or the results.</summary>
    public static string TrayWake(string dataFolder) => Name("Tray.Wake", dataFolder);

    /// <summary>Held by the process that shows the window.</summary>
    public static string Window(string dataFolder) => Name("Window", dataFolder);

    /// <summary>Signalled to bring the window forward.</summary>
    public static string WindowShow(string dataFolder) => Name("Window.Show", dataFolder);

    /// <summary>Where the check to show is left for the window.</summary>
    public static string WindowRequest(string dataFolder) => Name("Window.Request", dataFolder);

    private static string Name(string kind, string dataFolder)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataFolder);
        string folder = Path.TrimEndingDirectorySeparator(Path.GetFullPath(dataFolder)).ToUpperInvariant();
        string tag = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(folder)), 0, 8);
        return $@"Local\{ProductInfo.Name}.{kind}.{tag}";
    }
}

/// <summary>A claim to be the only process of its kind; held until disposed or the process ends.</summary>
[SupportedOSPlatform(MinimumWindows.Platform)]
public sealed class SingleInstance : IDisposable
{
    private readonly Mutex? _held;

    private SingleInstance(Mutex? held) => _held = held;

    /// <summary>For a process that goes ahead although it could not make the claim.</summary>
    public static SingleInstance Unclaimed => new(null);

    /// <summary>
    /// The claim, or null when another process holds it. Only the name being taken counts, so
    /// the claim holds whichever thread made it.
    /// </summary>
    public static SingleInstance? TryClaim(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        try
        {
            var mutex = new Mutex(initiallyOwned: false, name, out bool createdNew);
            if (createdNew)
            {
                return new SingleInstance(mutex);
            }

            mutex.Dispose();
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            // Held by a process this one may not look at (one that runs as administrator).
            return null;
        }
        catch (WaitHandleCannotBeOpenedException)
        {
            // The name is taken by something that is not SecReview's. Better two copies than none.
            return Unclaimed;
        }
    }

    public void Dispose() => _held?.Dispose();
}

/// <summary>A named signal from one process to another: "look again".</summary>
[SupportedOSPlatform(MinimumWindows.Platform)]
public sealed class WakeSignal : IDisposable
{
    private readonly EventWaitHandle _event;
    private readonly RegisteredWaitHandle _wait;

    private WakeSignal(EventWaitHandle handle, Action onWake)
    {
        _event = handle;
        _wait = ThreadPool.RegisterWaitForSingleObject(handle, (_, _) => onWake(), null, Timeout.Infinite, executeOnlyOnce: false);
    }

    /// <summary>
    /// Calls <paramref name="onWake"/>, on some other thread, each time the signal is sent.
    /// Null when the signal could not be set up; the caller then simply is not woken.
    /// </summary>
    public static WakeSignal? Listen(string name, Action onWake)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(onWake);
        try
        {
            return new WakeSignal(new EventWaitHandle(initialState: false, EventResetMode.AutoReset, name), onWake);
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or WaitHandleCannotBeOpenedException or IOException)
        {
            return null;
        }
    }

    /// <summary>Sends the signal. False when nobody listens.</summary>
    public static bool Send(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        try
        {
            if (EventWaitHandle.TryOpenExisting(name, out EventWaitHandle? handle))
            {
                using (handle)
                {
                    return handle.Set();
                }
            }
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or IOException)
        {
            // A listener this process may not signal counts as none.
        }

        return false;
    }

    public void Dispose()
    {
        // Wait until the listening has really stopped, so that no call arrives after this
        // returns and the signal is gone for senders. Not forever: a call that is itself
        // disposing the listener must not wait for itself.
        using (var stopped = new ManualResetEvent(false))
        {
            if (_wait.Unregister(stopped))
            {
                stopped.WaitOne(TimeSpan.FromSeconds(2));
            }
        }

        _event.Dispose();
    }
}

/// <summary>
/// How a second start of the window hands over to the one that is open: it leaves the check
/// to show, if any, and signals. What is left is only ever a check's identifier, and the
/// window takes it as nothing more than that.
/// </summary>
[SupportedOSPlatform(MinimumWindows.Platform)]
public sealed class ShowRequests : IDisposable
{
    private const int Size = 128;

    private readonly MemoryMappedFile? _memory;
    private readonly WakeSignal _signal;

    private ShowRequests(MemoryMappedFile? memory, string eventName, Action<string?> onShow)
    {
        _memory = memory;
        _signal = WakeSignal.Listen(eventName, () => onShow(Take()))
            ?? throw new InvalidOperationException("The signal could not be set up.");
    }

    /// <summary>
    /// Calls <paramref name="onShow"/>, on some other thread, when another start asks for the
    /// window: with the check to show, or null for the window as it is. Null when the signal
    /// could not be set up.
    /// </summary>
    public static ShowRequests? Listen(string eventName, string memoryName, Action<string?> onShow)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(eventName);
        ArgumentException.ThrowIfNullOrWhiteSpace(memoryName);
        ArgumentNullException.ThrowIfNull(onShow);

        MemoryMappedFile? memory = null;
        try
        {
            memory = MemoryMappedFile.CreateNew(memoryName, Size);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Without it the window still comes forward, only not on a check.
        }

        try
        {
            return new ShowRequests(memory, eventName, onShow);
        }
        catch (InvalidOperationException)
        {
            memory?.Dispose();
            return null;
        }
    }

    /// <summary>Asks the open window to come forward, on a check when one is named. False when no window listens.</summary>
    public static bool Send(string eventName, string memoryName, string? checkId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(eventName);
        ArgumentException.ThrowIfNullOrWhiteSpace(memoryName);

        try
        {
            using MemoryMappedFile memory = MemoryMappedFile.OpenExisting(memoryName, MemoryMappedFileRights.ReadWrite);
            using MemoryMappedViewAccessor view = memory.CreateViewAccessor(0, Size);
            byte[] bytes = new byte[Size];
            if (ErrorReports.IsCheckId(checkId))
            {
                bytes[0] = (byte)Encoding.ASCII.GetBytes(checkId, bytes.AsSpan(1));
            }

            view.WriteArray(0, bytes, 0, Size);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // The window still comes forward, only not on the check.
        }

        return WakeSignal.Send(eventName);
    }

    /// <summary>The check that was left, once; null when there is none or it is not an identifier.</summary>
    private string? Take()
    {
        if (_memory is null)
        {
            return null;
        }

        try
        {
            using MemoryMappedViewAccessor view = _memory.CreateViewAccessor(0, Size);
            byte[] bytes = new byte[Size];
            view.ReadArray(0, bytes, 0, Size);
            view.WriteArray(0, new byte[Size], 0, Size);

            int length = bytes[0];
            if (length is 0 or > Size - 1)
            {
                return null;
            }

            string text = Encoding.ASCII.GetString(bytes, 1, length);
            return ErrorReports.IsCheckId(text) ? text : null;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    public void Dispose()
    {
        _signal.Dispose();
        _memory?.Dispose();
    }
}

/// <summary>Bringing a window in front of the others, which Windows only lets the program in front decide.</summary>
[SupportedOSPlatform(MinimumWindows.Platform)]
public static class Foreground
{
    /// <summary>
    /// Called by a process the user just started, before it hands over to the window that is
    /// open already: lets that window come forward in its place.
    /// </summary>
    public static void HandOver() => PInvoke.AllowSetForegroundWindow(PInvoke.ASFW_ANY);

    /// <summary>Brings a window forward, out of the taskbar if it was minimised.</summary>
    public static void Bring(nint window)
    {
        var handle = new HWND(window);
        if (PInvoke.IsIconic(handle))
        {
            PInvoke.ShowWindow(handle, SHOW_WINDOW_CMD.SW_RESTORE);
        }

        PInvoke.SetForegroundWindow(handle);
    }
}
