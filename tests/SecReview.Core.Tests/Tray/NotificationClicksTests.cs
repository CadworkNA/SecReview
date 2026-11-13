using System.Runtime.Versioning;
using SecReview.Probing.Windows;
using SecReview.Tray;
using SecReview.Tray.Windows;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.System.Com;
using Windows.Win32.UI.Notifications;

namespace SecReview.Tests.Tray;

/// <summary>
/// The click comes through COM as the notification platform sends it: the class is asked
/// for as a local server and Activate is called on what COM hands back. Client and class are
/// in one process here, so no proxy is involved; the click from another process is in
/// scripts\test-install.ps1. The class is offered under a made-up identifier for the test
/// process only; nothing is registered.
/// </summary>
[TestClass]
[SupportedOSPlatform("windows10.0.19041")]
public sealed class NotificationClicksTests
{
    private static readonly TimeSpan Patience = TimeSpan.FromSeconds(20);

    [TestMethod]
    public async Task AClick_IsHandedOverWithItsArguments()
    {
        Guid activator = Guid.NewGuid();
        Task<(bool, string?)> waiting = Receive(activator, Patience);

        Assert.AreEqual(0, await Click(activator, AppNotification.AppId, "show:firewall.enabled"));

        Assert.AreEqual((true, "show:firewall.enabled"), await waiting);
    }

    [TestMethod]
    public async Task OnlyTheFirstClickCounts()
    {
        Guid activator = Guid.NewGuid();
        Task<(bool, string?)> waiting = Receive(activator, Patience);

        // Two clicks on the one callback; both answer "done": Windows has nothing to do with a
        // click that is not taken.
        Assert.AreEqual(0, await Click(activator, AppNotification.AppId, "show:a", "show:b"));

        Assert.AreEqual((true, "show:a"), await waiting);
    }

    [TestMethod]
    public async Task OverlongArguments_AreNotRead()
    {
        Guid activator = Guid.NewGuid();
        Task<(bool, string?)> waiting = Receive(activator, Patience);

        Assert.AreEqual(0, await Click(activator, AppNotification.AppId, "show:" + new string('a', 5000)));

        Assert.AreEqual((true, (string?)null), await waiting);
    }

    [TestMethod]
    public async Task WithoutAClick_TheWaitEnds_AndTheClassIsWithdrawn()
    {
        Guid activator = Guid.NewGuid();

        Assert.AreEqual((false, (string?)null), await Receive(activator, TimeSpan.FromMilliseconds(300)));

        // Withdrawn: Windows now looks for it in the registry, where it is not.
        Assert.AreEqual(unchecked((int)0x80040154), await Click(activator, AppNotification.AppId, retry: false, "show"), "REGDB_E_CLASSNOTREG");
    }

    private static Task<(bool Arrived, string? Arguments)> Receive(Guid activator, TimeSpan timeout) => Task.Run(() =>
    {
        bool arrived = NotificationClicks.TryReceive(activator, timeout, out string? arguments);
        return (arrived, arguments);
    });

    /// <summary>What the notification platform does for a click: create the class as a local server and call Activate, once per click.</summary>
    /// <returns>What creating the class or the first failing Activate returned.</returns>
    private static Task<int> Click(Guid activator, string appId, params string[] clicks) => Click(activator, appId, retry: true, clicks);

    private static Task<int> Click(Guid activator, string appId, bool retry, params string[] clicks) =>
        Task.Run(() => ClickNow(activator, appId, clicks, retry));

    private static unsafe int ClickNow(Guid activator, string appId, string[] clicks, bool retry)
    {
        using ComScope com = ComScope.Enter();
        Guid callbackId = typeof(INotificationActivationCallback).GUID;
        DateTime giveUp = DateTime.UtcNow + Patience;
        while (true)
        {
            INotificationActivationCallback* callback = null;
            HRESULT created = PInvoke.CoCreateInstance(&activator, null, CLSCTX.CLSCTX_LOCAL_SERVER, &callbackId, (void**)&callback);
            if (created.Failed)
            {
                // The class is offered a moment after the wait starts.
                if (retry && DateTime.UtcNow < giveUp)
                {
                    Thread.Sleep(50);
                    continue;
                }

                return created.Value;
            }

            try
            {
                fixed (char* id = appId)
                {
                    foreach (string arguments in clicks)
                    {
                        fixed (char* invoked = arguments)
                        {
                            callback->Activate(id, invoked, null, 0);
                        }
                    }

                    return 0;
                }
            }
            catch (System.Runtime.InteropServices.COMException exception)
            {
                return exception.HResult;
            }
            finally
            {
                callback->Release();
            }
        }
    }
}