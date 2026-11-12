using System.Runtime.Versioning;
using SecReview.Instances;

namespace SecReview.Tests.Instances;

/// <summary>
/// These use real named objects of Windows, under names made up per test. They exist only
/// while the test runs and change nothing on the PC.
/// </summary>
[TestClass]
[SupportedOSPlatform("windows10.0.19041")]
public sealed class InstancesTests
{
    private static readonly TimeSpan Soon = TimeSpan.FromSeconds(10);

    private readonly string _folder = Path.Combine(Path.GetTempPath(), "SecReview.Tests." + Guid.NewGuid().ToString("N"));

    [TestMethod]
    public void Names_AreLocalToTheSession_AndDifferPerDataFolderAndKind()
    {
        string tray = InstanceNames.Tray(_folder);

        StringAssert.StartsWith(tray, @"Local\SecReview.Tray.");
        Assert.AreEqual(tray, InstanceNames.Tray(_folder.ToUpperInvariant() + Path.DirectorySeparatorChar), "the same folder, written differently");
        Assert.AreNotEqual(tray, InstanceNames.Tray(_folder + "2"));
        Assert.AreEqual(
            5,
            new[] { tray, InstanceNames.TrayWake(_folder), InstanceNames.Window(_folder), InstanceNames.WindowShow(_folder), InstanceNames.WindowRequest(_folder) }.Distinct().Count());
        Assert.IsFalse(tray.Contains(Path.GetFileName(_folder), StringComparison.OrdinalIgnoreCase), "the folder itself is not in the name");
    }

    [TestMethod]
    public void OnlyOneClaim_IsHeldAtATime()
    {
        string name = InstanceNames.Tray(_folder);

        using (SingleInstance? first = SingleInstance.TryClaim(name))
        {
            Assert.IsNotNull(first);
            Assert.IsNull(SingleInstance.TryClaim(name));
        }

        using SingleInstance? again = SingleInstance.TryClaim(name);
        Assert.IsNotNull(again, "free again once the holder let go");
    }

    [TestMethod]
    public void ASignal_WakesTheListener_AndWithoutOneNothingHappens()
    {
        string name = InstanceNames.TrayWake(_folder);
        Assert.IsFalse(WakeSignal.Send(name), "nobody listens");

        using var woken = new SemaphoreSlim(0);
        using (WakeSignal? listener = WakeSignal.Listen(name, () => woken.Release()))
        {
            Assert.IsNotNull(listener);
            Assert.IsTrue(WakeSignal.Send(name));
            Assert.IsTrue(woken.Wait(Soon));
            Assert.IsTrue(WakeSignal.Send(name));
            Assert.IsTrue(woken.Wait(Soon), "it keeps listening");
        }

        // Windows lets go of the signal a moment after its last user has.
        Assert.IsTrue(SpinWait.SpinUntil(() => !WakeSignal.Send(name), Soon), "gone with its listener");
    }

    [TestMethod]
    public void ASecondStart_HandsTheCheckToShowToTheWindow_Once()
    {
        string signal = InstanceNames.WindowShow(_folder);
        string memory = InstanceNames.WindowRequest(_folder);
        Assert.IsFalse(ShowRequests.Send(signal, memory, "firewall.enabled"), "no window is open");

        using var asked = new SemaphoreSlim(0);
        var shown = new List<string?>();
        using ShowRequests? window = ShowRequests.Listen(signal, memory, checkId =>
        {
            shown.Add(checkId);
            asked.Release();
        });
        Assert.IsNotNull(window);

        Assert.IsTrue(ShowRequests.Send(signal, memory, "firewall.enabled"));
        Assert.IsTrue(asked.Wait(Soon));
        Assert.IsTrue(ShowRequests.Send(signal, memory, null));
        Assert.IsTrue(asked.Wait(Soon));

        CollectionAssert.AreEqual(new string?[] { "firewall.enabled", null }, shown, "a check is shown once, not again by the next plain start");
    }

    [TestMethod]
    [DataRow(@"..\..\somewhere")]
    [DataRow("two words")]
    [DataRow("")]
    public void WhatIsNotACheckIdentifier_IsNotHandedOver(string text)
    {
        string signal = InstanceNames.WindowShow(_folder);
        string memory = InstanceNames.WindowRequest(_folder);
        using var asked = new SemaphoreSlim(0);
        string? shown = "untouched";
        using ShowRequests? window = ShowRequests.Listen(signal, memory, checkId =>
        {
            shown = checkId;
            asked.Release();
        });

        Assert.IsTrue(ShowRequests.Send(signal, memory, text));
        Assert.IsTrue(asked.Wait(Soon));

        Assert.IsNull(shown);
    }

    [TestMethod]
    public void WhatAnotherProgramLeftInTheRequest_IsOnlyEverTakenAsAnIdentifier()
    {
        string signal = InstanceNames.WindowShow(_folder);
        string memory = InstanceNames.WindowRequest(_folder);
        using var asked = new SemaphoreSlim(0);
        string? shown = "untouched";
        using ShowRequests? window = ShowRequests.Listen(signal, memory, checkId =>
        {
            shown = checkId;
            asked.Release();
        });

        // Not through Send: a length that runs past the end, and text that is no identifier.
        foreach (byte[] planted in new[] { Bytes(200, "firewall.enabled"), Bytes(12, @"C:\made\up\x") })
        {
            using (var other = System.IO.MemoryMappedFiles.MemoryMappedFile.OpenExisting(memory))
            using (System.IO.MemoryMappedFiles.MemoryMappedViewAccessor view = other.CreateViewAccessor())
            {
                view.WriteArray(0, planted, 0, planted.Length);
            }

            Assert.IsTrue(WakeSignal.Send(signal));
            Assert.IsTrue(asked.Wait(Soon));
            Assert.IsNull(shown);
            shown = "untouched";
        }

        static byte[] Bytes(byte length, string text) => [length, .. System.Text.Encoding.ASCII.GetBytes(text)];
    }
}
