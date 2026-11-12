using SecReview.Probing;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.Probing;

[TestClass]
public sealed class ProbeModelTests
{
    [TestMethod]
    [DataRow(1, DriveEncryptionState.On)]
    [DataRow(2, DriveEncryptionState.Off)]
    [DataRow(0, DriveEncryptionState.Other)]
    [DataRow(3, DriveEncryptionState.Other)]
    [DataRow(5, DriveEncryptionState.Other)]
    [DataRow(6, DriveEncryptionState.Other)]
    [DataRow(99, DriveEncryptionState.Other)]
    public void DriveEncryption_OnlyOnAndOffAreTakenAsDefinite(int raw, DriveEncryptionState expected)
    {
        Assert.AreEqual(expected, DriveEncryption.Interpret(raw));
    }

    [TestMethod]
    public void DriveEncryption_NoValue_IsNotReported_NeverOn()
    {
        Assert.AreEqual(DriveEncryptionState.NotReported, DriveEncryption.Interpret(null));
    }

    [TestMethod]
    public void DriveEncryption_AStateNobodySet_IsUnreadable_NeverOn()
    {
        var slots = new DriveEncryptionState[1];

        Assert.AreEqual(DriveEncryptionState.Unreadable, slots[0]);
    }

    [TestMethod]
    [DataRow(@"ROOT\CIMV2")]
    [DataRow(@"root\Microsoft\Windows\Defender")]
    [DataRow("ROOT")]
    public void WmiNamespace_OnThisPc_IsAccepted(string wmiNamespace)
    {
        Assert.IsTrue(WmiNames.IsLocalNamespace(wmiNamespace));
    }

    [TestMethod]
    [DataRow(@"\\OTHERPC\ROOT\CIMV2", DisplayName = "another computer")]
    [DataRow(@"\\.\ROOT\CIMV2", DisplayName = "explicit local computer prefix")]
    [DataRow(@"\ROOT\CIMV2", DisplayName = "leading backslash")]
    [DataRow(@"ROOT\\CIMV2", DisplayName = "empty segment")]
    [DataRow(@"ROOT\CIMV2\", DisplayName = "trailing backslash")]
    [DataRow(@"CIMV2", DisplayName = "does not start at ROOT")]
    [DataRow(@"ROOT\CIM V2", DisplayName = "space")]
    [DataRow(@"ROOT\CIMV2' OR '1'='1", DisplayName = "query text")]
    [DataRow("", DisplayName = "empty")]
    public void WmiNamespace_ThatCouldReachElsewhereOrIsMalformed_IsRefused(string wmiNamespace)
    {
        Assert.IsFalse(WmiNames.IsLocalNamespace(wmiNamespace));
    }

    [TestMethod]
    [DataRow("Win32_OperatingSystem", true)]
    [DataRow("MSFT_MpComputerStatus", true)]
    [DataRow("Caption, Name", false)]
    [DataRow("Win32_Process WHERE 1=1", false)]
    [DataRow("*", false)]
    [DataRow("", false)]
    public void WmiClassAndPropertyNames_MustBePlainIdentifiers(string name, bool expected)
    {
        Assert.AreEqual(expected, WmiNames.IsIdentifier(name));
    }

    [TestMethod]
    public void WmiObject_ReadsEachKindOfValue_ByNameIgnoringCase()
    {
        WmiObject item = FakeProbes.Wmi(
            ("Caption", "Example"),
            ("Count", 42L),
            ("Enabled", true),
            ("Codes", (IReadOnlyList<long>)[1L, 2L]),
            ("Names", (IReadOnlyList<string>)["a", "b"]));

        Assert.AreEqual("Example", item.Text("caption"));
        Assert.AreEqual(42L, item.Number("COUNT"));
        Assert.AreEqual(true, item.Flag("Enabled"));
        CollectionAssert.AreEqual(new[] { 1L, 2L }, item.Numbers("Codes").ToArray());
        CollectionAssert.AreEqual(new[] { "a", "b" }, item.Texts("Names").ToArray());
    }

    [TestMethod]
    public void WmiObject_ParsesNumbersThatWmiHandsOverAsText()
    {
        WmiObject item = FakeProbes.Wmi(("Size", "1099511627776"), ("NotANumber", "abc"));

        Assert.AreEqual(1099511627776L, item.Number("Size"));
        Assert.IsNull(item.Number("NotANumber"));
    }

    [TestMethod]
    public void WmiObject_MissingEmptyOrMistypedProperty_IsNullOrEmpty_NeverADefaultValue()
    {
        WmiObject item = FakeProbes.Wmi(("Empty", null), ("Text", "x"));

        Assert.IsNull(item.Text("Missing"));
        Assert.IsNull(item.Number("Missing"));
        Assert.IsNull(item.Flag("Missing"));
        Assert.IsNull(item.Flag("Empty"));
        Assert.IsNull(item.Flag("Text"), "text must not be read as a boolean");
        Assert.AreEqual(0, item.Numbers("Missing").Count);
        Assert.AreEqual(0, item.Texts("Text").Count);
    }

    [TestMethod]
    public void RegistryValue_KeepsItsTypeAndData()
    {
        Assert.AreEqual(RegistryValueType.Number, RegistryValue.FromNumber(4294967295).Type);
        Assert.AreEqual(4294967295, RegistryValue.FromNumber(4294967295).Number);
        Assert.AreEqual("x", RegistryValue.FromText("x").Text);
        Assert.AreEqual(2, RegistryValue.FromTextList(["a", "b"]).TextList.Count);
        Assert.AreEqual(3, RegistryValue.FromBinary([1, 2, 3]).Binary.Length);
        Assert.AreEqual(RegistryValueType.Other, RegistryValue.Other.Type);
    }
}
