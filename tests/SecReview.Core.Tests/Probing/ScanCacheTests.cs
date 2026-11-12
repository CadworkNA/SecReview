using SecReview.Probing;
using SecReview.Probing.Windows;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.Probing;

[TestClass]
public sealed class ScanCacheTests
{
    private sealed class CountingUpdateProbe : IWindowsUpdateProbe
    {
        public int Calls { get; private set; }

        public ProbeResult<WindowsUpdateStatus> GetStatus()
        {
            Calls++;
            return ProbeFailure.Failed($"Failed on call {Calls}.");
        }
    }

    [TestMethod]
    public void ASharedReading_IsTakenOncePerScan_AndAgainForTheNextScan()
    {
        var counting = new CountingUpdateProbe();
        SystemProbes probes = new FakeProbes().Build() with { WindowsUpdate = counting };

        SystemProbes firstScan = ScanCache.ForOneScan(probes);
        _ = firstScan.WindowsUpdate.GetStatus();
        _ = firstScan.WindowsUpdate.GetStatus();
        ProbeResult<WindowsUpdateStatus> third = firstScan.WindowsUpdate.GetStatus();

        Assert.AreEqual(1, counting.Calls);
        Assert.AreEqual("Failed on call 1.", third.Detail, "a failed reading is kept too, so every check gives the same reason");

        _ = ScanCache.ForOneScan(probes).WindowsUpdate.GetStatus();
        Assert.AreEqual(2, counting.Calls, "checking again reads afresh");
    }

    [TestMethod]
    public void TheOtherReadings_PassStraightThrough()
    {
        var fake = new FakeProbes
        {
            Tpm = ProbeResult<TpmVersion>.Ok(TpmVersion.Version20),
            Firmware = ProbeResult<FirmwareKind>.Ok(FirmwareKind.Uefi),
            Power = ProbeResult<PowerSettings>.Ok(FakeProbes.Laptop(5)),
        };

        SystemProbes cached = ScanCache.ForOneScan(fake.Build());

        Assert.AreEqual(TpmVersion.Version20, cached.Platform.GetTpm().Value);
        Assert.AreEqual(FirmwareKind.Uefi, cached.Platform.GetFirmware().Value);
        Assert.IsTrue(cached.Power.GetSettings().IsOk);
        Assert.IsFalse(cached.Platform.GetCodeIntegrity().IsOk, "not set up in this test");
        Assert.AreSame(fake.Build().Registry.GetType(), cached.Registry.GetType());
    }

    [TestMethod]
    public void AnUpdateDateOfZero_MeansNever_NotAFailure()
    {
        Assert.IsNull(WindowsUpdateDates.FromAutomationDate(0));
        Assert.AreEqual(
            new DateTimeOffset(2026, 11, 3, 12, 0, 0, TimeSpan.Zero),
            WindowsUpdateDates.FromAutomationDate(new DateTime(2026, 11, 3, 12, 0, 0, DateTimeKind.Utc).ToOADate()));
        Assert.ThrowsExactly<ArgumentException>(() => WindowsUpdateDates.FromAutomationDate(1e300));
    }
}
