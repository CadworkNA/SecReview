using SecReview.SupplyChain;

namespace SecReview.Tests.SupplyChain;

[TestClass]
public sealed class DurationsTests
{
    [TestMethod]
    [DataRow("7 days", 168)]
    [DataRow("1 week", 168)]
    [DataRow("24 hours", 24)]
    [DataRow("36h", 36)]
    [DataRow("3d", 72)]
    [DataRow("1 week 2 days", 216)]
    [DataRow("1w, 12 hrs", 180)]
    [DataRow("P7D", 168)]
    [DataRow("p7d", 168)]
    [DataRow("P1W", 168)]
    [DataRow("PT48H", 48)]
    [DataRow("P1DT12H", 36)]
    [DataRow(" 10 days ", 240)]
    public void Uv_LengthsOfTime(string text, int hours)
    {
        Cooldown cooldown = Durations.ParseUv(text);

        Assert.AreEqual(CooldownKind.Relative, cooldown.Kind);
        Assert.AreEqual(TimeSpan.FromHours(hours), cooldown.Length);
    }

    [TestMethod]
    [DataRow("2026-11-01")]
    [DataRow("2026-11-01T00:00:00Z")]
    [DataRow("2026-11-01 12:30:00+01:00")]
    public void Uv_FixedDates(string text)
    {
        Assert.AreEqual(CooldownKind.AbsoluteDate, Durations.ParseUv(text).Kind);
        Assert.AreEqual(CooldownKind.AbsoluteDate, Durations.ParsePip(text).Kind);
    }

    [TestMethod]
    public void Uv_False_IsSwitchedOff()
    {
        Assert.AreEqual(CooldownKind.Disabled, Durations.ParseUv("false").Kind);
    }

    [TestMethod]
    [DataRow("")]
    [DataRow("   ")]
    [DataRow("soon")]
    [DataRow("7")]
    [DataRow("1 month")]
    [DataRow("1 year")]
    [DataRow("P1M")]
    [DataRow("P")]
    [DataRow("7 days ago")]
    [DataRow("-7 days")]
    [DataRow("true")]
    public void Uv_WhatUvWouldRefuse_IsInvalid(string text)
    {
        Assert.AreEqual(CooldownKind.Invalid, Durations.ParseUv(text).Kind);
    }

    [TestMethod]
    public void Pip_TakesIsoLengthsOnly()
    {
        Assert.AreEqual(TimeSpan.FromDays(7), Durations.ParsePip("P7D").Length);
        Assert.AreEqual(CooldownKind.Invalid, Durations.ParsePip("7 days").Kind);
        Assert.AreEqual(CooldownKind.Invalid, Durations.ParsePip(null).Kind);
    }

    [TestMethod]
    public void ShortForm_AsYarnAndPdmWriteIt()
    {
        TimeSpan minute = TimeSpan.FromMinutes(1);

        Assert.AreEqual(TimeSpan.FromDays(7), Durations.ParseShort("7d", minute).Length);
        Assert.AreEqual(TimeSpan.FromHours(168), Durations.ParseShort("168h", minute).Length);
        Assert.AreEqual(TimeSpan.FromDays(14), Durations.ParseShort("2w", minute).Length);
        Assert.AreEqual(TimeSpan.FromMinutes(10080), Durations.ParseShort("10080", minute).Length, "a bare number is minutes for Yarn");
        Assert.AreEqual(CooldownKind.Invalid, Durations.ParseShort("10080", bareNumberUnit: null).Kind, "PDM needs a unit");
        Assert.AreEqual(CooldownKind.Invalid, Durations.ParseShort("7x", minute).Kind);
        Assert.AreEqual(CooldownKind.Invalid, Durations.ParseShort("d7", minute).Kind);
    }

    [TestMethod]
    public void Numbers_InAFixedUnit()
    {
        Assert.AreEqual(TimeSpan.FromDays(7), Durations.FromNumber(7, TimeSpan.FromDays(1)).Length);
        Assert.AreEqual(TimeSpan.FromDays(7), Durations.FromNumber(10080, TimeSpan.FromMinutes(1)).Length);
        Assert.AreEqual(TimeSpan.FromDays(7), Durations.FromNumber(604800, TimeSpan.FromSeconds(1)).Length);
        Assert.AreEqual(TimeSpan.Zero, Durations.FromNumber(0, TimeSpan.FromDays(1)).Length);
        Assert.AreEqual(CooldownKind.Invalid, Durations.FromNumber(-1, TimeSpan.FromDays(1)).Kind);
        Assert.AreEqual(CooldownKind.Invalid, Durations.FromNumber(long.MaxValue, TimeSpan.FromDays(1)).Kind, "absurd lengths are not accepted");
    }

    [TestMethod]
    [DataRow("12.19.0", 12, 19, 0)]
    [DataRow("v0.12.19", 0, 12, 19)]
    [DataRow("11.10", 11, 10, 0)]
    [DataRow("4", 4, 0, 0)]
    [DataRow("2.27.0rc1", 2, 27, 0)]
    [DataRow("1.3.0-canary.5", 1, 3, 0)]
    [DataRow(" 0.9.17 ", 0, 9, 17)]
    public void Versions_AreRead(string text, int major, int minor, int patch)
    {
        Assert.AreEqual(new ToolVersion(major, minor, patch), ToolVersion.Parse(text));
    }

    [TestMethod]
    [DataRow(null)]
    [DataRow("")]
    [DataRow("latest")]
    [DataRow("nightly")]
    [DataRow(".5")]
    public void WhatIsNotAVersion_IsNone(string? text)
    {
        Assert.IsNull(ToolVersion.Parse(text));
    }

    [TestMethod]
    public void Versions_CompareByNumber_NotByText()
    {
        Assert.IsTrue(new ToolVersion(0, 12, 19) >= new ToolVersion(0, 9, 17));
        Assert.IsTrue(new ToolVersion(0, 9, 16) < new ToolVersion(0, 9, 17));
        Assert.IsTrue(new ToolVersion(11, 10) > new ToolVersion(11, 9, 9));
        Assert.IsTrue(new ToolVersion(2) <= new ToolVersion(2, 0, 0));
        Assert.AreEqual("0.9.17", new ToolVersion(0, 9, 17).ToString());
    }
}
