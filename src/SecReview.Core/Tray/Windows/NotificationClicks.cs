using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using SecReview.Probing.Windows;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.System.Com;

namespace SecReview.Tray.Windows;

/// <summary>
/// Takes a click on one of SecReview's notifications from Windows. Setup registers
/// <see cref="AppNotification.ActivatorId"/> to start <c>SecReview.exe --notification-click</c>;
/// that process offers Windows the object it asks for (INotificationActivationCallback) and
/// gets the click's arguments through it.
/// </summary>
/// <remarks>
/// Two plain COM objects that live as long as the process: a class factory and the callback.
/// They hold no state of their own and are never freed, so they need no reference counts.
/// Whatever arrives is only text: <see cref="AppNotification.TryReadArguments"/> decides.
/// </remarks>
[SupportedOSPlatform(MinimumWindows.Platform)]
public static unsafe class NotificationClicks
{
    private const int S_OK = 0;
    private const int E_NOINTERFACE = unchecked((int)0x80004002);
    private const int E_POINTER = unchecked((int)0x80004003);
    private const int CLASS_E_NOAGGREGATION = unchecked((int)0x80040110);

    /// <summary>Arguments longer than this are not read, and not SecReview's.</summary>
    private const int MaximumArguments = 1024;

    private static readonly Guid IUnknownId = new("00000000-0000-0000-C000-000000000046");
    private static readonly Guid IClassFactoryId = new("00000001-0000-0000-C000-000000000046");
    private static readonly Guid CallbackId = new("53E31837-6600-4A81-9395-75CFFE746F94");

    private static readonly nint s_factory = NewObject(
    [
        (nint)(delegate* unmanaged<void*, Guid*, void**, int>)&FactoryQueryInterface,
        (nint)(delegate* unmanaged<void*, uint>)&AddRef,
        (nint)(delegate* unmanaged<void*, uint>)&Release,
        (nint)(delegate* unmanaged<void*, void*, Guid*, void**, int>)&CreateInstance,
        (nint)(delegate* unmanaged<void*, int, int>)&LockServer,
    ]);

    private static readonly nint s_callback = NewObject(
    [
        (nint)(delegate* unmanaged<void*, Guid*, void**, int>)&CallbackQueryInterface,
        (nint)(delegate* unmanaged<void*, uint>)&AddRef,
        (nint)(delegate* unmanaged<void*, uint>)&Release,
        (nint)(delegate* unmanaged<void*, char*, char*, void*, uint, int>)&Activate,
    ]);

    private static Waiter? s_waiter;

    /// <summary>
    /// Offers Windows the callback under <paramref name="activator"/> and waits for the click.
    /// Only the first click counts.
    /// </summary>
    /// <param name="activator">The class Windows was asked for (<see cref="AppNotification.ActivatorId"/>).</param>
    /// <param name="timeout">How long to wait for Windows.</param>
    /// <param name="arguments">The click's arguments; null when none came, or they were too long to be SecReview's.</param>
    /// <returns>Whether a click came in time.</returns>
    /// <exception cref="InvalidOperationException">Windows did not take the callback.</exception>
    public static bool TryReceive(Guid activator, TimeSpan timeout, out string? arguments)
    {
        // Calls from other processes reach a multithreaded apartment without a message loop.
        // The caller's thread (the app's main one) is single-threaded, so the wait is elsewhere.
        (bool Arrived, string? Arguments)? received = null;
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try
            {
                received = Wait(activator, timeout);
            }
#pragma warning disable CA1031 // Handed to the caller's thread below.
            catch (Exception exception)
#pragma warning restore CA1031
            {
                failure = exception;
            }
        })
        {
            IsBackground = true,
            Name = "Notification click",
        };
        thread.SetApartmentState(ApartmentState.MTA);
        thread.Start();
        thread.Join();

        if (failure is not null)
        {
            throw new InvalidOperationException("The notification click could not be taken.", failure);
        }

        arguments = received?.Arguments;
        return received?.Arrived ?? false;
    }

    private static (bool Arrived, string? Arguments) Wait(Guid activator, TimeSpan timeout)
    {
        using ComScope com = ComScope.Enter();
        var waiter = new Waiter();
        if (Interlocked.CompareExchange(ref s_waiter, waiter, null) is not null)
        {
            throw new InvalidOperationException("Notification clicks are already being taken.");
        }

        try
        {
            uint cookie;
            HRESULT registered = PInvoke.CoRegisterClassObject(&activator, (IUnknown*)s_factory, CLSCTX.CLSCTX_LOCAL_SERVER, REGCLS.REGCLS_MULTIPLEUSE, &cookie);
            Marshal.ThrowExceptionForHR(registered.Value);
            try
            {
                bool arrived = waiter.Arrived.Wait(timeout);
                return (arrived, arrived ? waiter.Arguments : null);
            }
            finally
            {
                PInvoke.CoRevokeClassObject(cookie);
            }
        }
        finally
        {
            Volatile.Write(ref s_waiter, null);
            waiter.Arrived.Dispose();
        }
    }

    private static nint NewObject(ReadOnlySpan<nint> methods)
    {
        nint* table = (nint*)NativeMemory.Alloc((nuint)(methods.Length * sizeof(nint)));
        methods.CopyTo(new Span<nint>(table, methods.Length));
        nint* instance = (nint*)NativeMemory.Alloc((nuint)sizeof(nint));
        *instance = (nint)table;
        return (nint)instance;
    }

    private static int QueryInterface(void* self, Guid* interfaceId, void** result, in Guid own)
    {
        if (result is null)
        {
            return E_POINTER;
        }

        if (interfaceId is not null && (*interfaceId == IUnknownId || *interfaceId == own))
        {
            *result = self;
            return S_OK;
        }

        *result = null;
        return E_NOINTERFACE;
    }

    [UnmanagedCallersOnly]
    private static int FactoryQueryInterface(void* self, Guid* interfaceId, void** result) =>
        QueryInterface(self, interfaceId, result, IClassFactoryId);

    [UnmanagedCallersOnly]
    private static int CallbackQueryInterface(void* self, Guid* interfaceId, void** result) =>
        QueryInterface(self, interfaceId, result, CallbackId);

    // The objects are never freed: these only have to keep COM's count above zero.
    [UnmanagedCallersOnly]
    private static uint AddRef(void* self) => 2;

    [UnmanagedCallersOnly]
    private static uint Release(void* self) => 1;

    [UnmanagedCallersOnly]
    private static int CreateInstance(void* self, void* outer, Guid* interfaceId, void** result)
    {
        if (result is null)
        {
            return E_POINTER;
        }

        *result = null;
        return outer is not null ? CLASS_E_NOAGGREGATION : QueryInterface((void*)s_callback, interfaceId, result, CallbackId);
    }

    [UnmanagedCallersOnly]
    private static int LockServer(void* self, int keep) => S_OK;

    /// <summary>INotificationActivationCallback.Activate: the user clicked the notification or its button.</summary>
    [UnmanagedCallersOnly]
    private static int Activate(void* self, char* appUserModelId, char* invokedArgs, void* data, uint count)
    {
        try
        {
            if (Volatile.Read(ref s_waiter) is { } waiter && Interlocked.Exchange(ref waiter.Taken, 1) == 0)
            {
                waiter.Arguments = Read(invokedArgs);
                waiter.Arrived.Set();
            }
        }
#pragma warning disable CA1031 // Nothing may be thrown back into Windows; a click that is lost opens nothing.
        catch (Exception)
#pragma warning restore CA1031
        {
        }

        return S_OK;
    }

    /// <summary>A text Windows handed over, read up to its end; null when there is none or it is too long.</summary>
    private static string? Read(char* text)
    {
        if (text is null)
        {
            return null;
        }

        for (int length = 0; length <= MaximumArguments; length++)
        {
            if (text[length] == '\0')
            {
                return new string(text, 0, length);
            }
        }

        return null;
    }

    private sealed class Waiter
    {
        public ManualResetEventSlim Arrived { get; } = new();

        public string? Arguments { get; set; }

        /// <summary>1 once a click was taken. A field: <see cref="Interlocked"/> needs one.</summary>
        public int Taken;
    }
}
