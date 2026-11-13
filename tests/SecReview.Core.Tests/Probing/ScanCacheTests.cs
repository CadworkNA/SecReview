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

    private sealed class CountingWmiProbe : IWmiProbe
    {
        public List<string> Questions { get; } = [];

        public ProbeResult<IReadOnlyList<WmiObject>> Query(
            string wmiNamespace, string className, IReadOnlyList<string> properties, WmiFlagFilter? only = null)
        {
            Questions.Add($"{className}:{string.Join('+', properties)}:{only?.Property}");
            return ProbeResult<IReadOnlyList<WmiObject>>.Ok([]);
        }
    }

    [TestMethod]
    public void TheSameWmiQuestion_IsAskedOnce_AndADifferentOneSeparately()
    {
        var counting = new CountingWmiProbe();
        SystemProbes scan = ScanCache.ForOneScan(new FakeProbes().Build() with { Wmi = counting });

        _ = scan.Wmi.Query(@"ROOT\CIMV2", "Win32_Share", ["Name", "Type"]);
        _ = scan.Wmi.Query(@"root\cimv2", "Win32_Share", ["Name", "Type"]);
        _ = scan.Wmi.Query(@"ROOT\CIMV2", "Win32_Share", ["Name"]);
        _ = scan.Wmi.Query(@"ROOT\CIMV2", "Win32_UserAccount", ["SID"], new WmiFlagFilter("LocalAccount", true));
        _ = scan.Wmi.Query(@"ROOT\CIMV2", "Win32_UserAccount", ["SID"]);

        CollectionAssert.AreEqual(
            new[] { "Win32_Share:Name+Type:", "Win32_Share:Name:", "Win32_UserAccount:SID:LocalAccount", "Win32_UserAccount:SID:" },
            counting.Questions);
    }

    private sealed class CountingAccessProbe : IAccessProbe
    {
        public List<string> Questions { get; } = [];

        public ProbeResult<SecurityReading> ReadPath(string path)
        {
            Questions.Add(path);
            return ProbeFailure.AccessDenied();
        }

        public ProbeResult<SecurityReading> ReadKey(RegistryRoot root, string keyPath)
        {
            Questions.Add($"{root}:{keyPath}");
            return ProbeFailure.NotFound();
        }

        public ProbeResult<DriveKind> Drive(char letter)
        {
            Questions.Add($"drive {letter}");
            return ProbeResult<DriveKind>.Ok(DriveKind.Fixed);
        }
    }

    [TestMethod]
    public void ThePermissionsOfOnePlace_AreReadOnce_WhateverTheSpellingOfItsCase()
    {
        var counting = new CountingAccessProbe();
        SystemProbes scan = ScanCache.ForOneScan(new FakeProbes().Build() with { Access = counting });

        _ = scan.Access.ReadPath(@"C:\Tools\Example");
        ProbeResult<SecurityReading> again = scan.Access.ReadPath(@"c:\tools\example");
        _ = scan.Access.ReadPath(@"C:\Tools");
        _ = scan.Access.ReadKey(RegistryRoot.LocalMachine, @"SOFTWARE\Example");
        _ = scan.Access.ReadKey(RegistryRoot.LocalMachine, @"SOFTWARE\Example");
        _ = scan.Access.ReadKey(RegistryRoot.CurrentUser, @"SOFTWARE\Example");
        _ = scan.Access.Drive('c');
        _ = scan.Access.Drive('C');

        Assert.AreEqual(ProbeStatus.AccessDenied, again.Status, "a failed reading is kept too");
        CollectionAssert.AreEqual(
            new[] { @"C:\Tools\Example", @"C:\Tools", @"LocalMachine:SOFTWARE\Example", @"CurrentUser:SOFTWARE\Example", "drive c" },
            counting.Questions);
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
