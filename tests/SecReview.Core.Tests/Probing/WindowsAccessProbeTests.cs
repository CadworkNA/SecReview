using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using SecReview.Probing;
using SecReview.Probing.Windows;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.Probing;

/// <summary>
/// Reads only the permissions of files these tests write into their own temporary folder, and
/// descriptors written out here. What the permissions mean is tested elsewhere, without Windows.
/// </summary>
[TestClass]
[SupportedOSPlatform("windows10.0.19041")]
public sealed class WindowsAccessProbeTests
{
    private static readonly WindowsAccessProbe Probe = new();

    private string _folder = string.Empty;

    public TestContext TestContext { get; set; } = null!;

    [TestInitialize]
    public void CreateFolder()
    {
        _folder = Path.Combine(TestContext.TestRunDirectory!, "access-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_folder);
    }

    [TestCleanup]
    public void RemoveFolder() => Directory.Delete(_folder, recursive: true);

    [TestMethod]
    public void AFileAndItsFolder_AreReadAsWhatTheyAre_WithAnOwnerAndEntries()
    {
        string file = Path.Combine(_folder, "program.exe");
        File.WriteAllText(file, "made up");

        ProbeResult<SecurityReading> ofFile = Probe.ReadPath(file);
        ProbeResult<SecurityReading> ofFolder = Probe.ReadPath(_folder);

        Assert.IsTrue(ofFile.IsOk, ofFile.Detail);
        Assert.AreEqual(SecuredKind.File, ofFile.Value!.Kind);
        Assert.IsTrue(ofFile.Value.HasList);
        Assert.IsTrue(ofFile.Value.Entries.Count > 0);
        StringAssert.StartsWith(ofFile.Value.Owner, "S-1-");
        Assert.IsTrue(ofFile.Value.Entries.All(e => e.Sid.StartsWith("S-1-", StringComparison.Ordinal)));

        Assert.IsTrue(ofFolder.IsOk, ofFolder.Detail);
        Assert.AreEqual(SecuredKind.Folder, ofFolder.Value!.Kind);
    }

    [TestMethod]
    public void AMissingPath_IsNotFound()
    {
        Assert.AreEqual(ProbeStatus.NotFound, Probe.ReadPath(Path.Combine(_folder, "none.exe")).Status);
        Assert.AreEqual(ProbeStatus.NotFound, Probe.ReadPath(Path.Combine(_folder, "no-folder", "none.exe")).Status);
    }

    [TestMethod]
    [DataRow(@"\\server\share\program.exe")]
    [DataRow(@"\\?\C:\Windows")]
    [DataRow(@"\\.\C:\Windows")]
    [DataRow(@"program.exe")]
    [DataRow(@"C:program.exe")]
    [DataRow("")]
    public void ANetworkDeviceOrRelativePath_IsRefused_WithoutBeingOpened(string path)
    {
        ProbeResult<SecurityReading> result = Probe.ReadPath(path);

        Assert.AreEqual(ProbeStatus.Failed, result.Status);
        StringAssert.Contains(result.Detail, "not a path on this PC");
    }

    [TestMethod]
    public void ALink_IsNotFollowed()
    {
        string target = Path.Combine(_folder, "target");
        string link = Path.Combine(_folder, "link");
        Directory.CreateDirectory(target);
        try
        {
            Directory.CreateSymbolicLink(link, target);
        }
        catch (IOException)
        {
            Assert.Inconclusive("This account may not create links.");
        }
        catch (UnauthorizedAccessException)
        {
            Assert.Inconclusive("This account may not create links.");
        }

        ProbeResult<SecurityReading> result = Probe.ReadPath(link);

        Assert.AreEqual(ProbeStatus.Failed, result.Status);
        Assert.AreEqual(IAccessProbe.LinkDetail, result.Detail);
    }

    [TestMethod]
    public void AStoredDescriptor_BecomesPlainEntries_InOrder_WithoutAuditEntries()
    {
        var users = new SecurityIdentifier(FakeAccess.Users);
        var everyone = new SecurityIdentifier(FakeAccess.Everyone);
        var list = new RawAcl(GenericAcl.AclRevision, 4);
        list.InsertAce(0, new CommonAce(AceFlags.None, AceQualifier.AccessDenied, 0x2, everyone, isCallback: false, opaque: null));
        list.InsertAce(1, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x1200A9, users, isCallback: false, opaque: null));
        list.InsertAce(
            2,
            new CommonAce(
                AceFlags.InheritOnly | AceFlags.ContainerInherit, AceQualifier.AccessAllowed, unchecked((int)0x10000000), users, isCallback: false, opaque: null));
        list.InsertAce(3, new CommonAce(AceFlags.None, AceQualifier.SystemAudit, 0x2, everyone, isCallback: false, opaque: null));
        var descriptor = new RawSecurityDescriptor(
            ControlFlags.DiscretionaryAclPresent, new SecurityIdentifier(FakeAccess.Administrators), group: null, systemAcl: null, list);
        byte[] bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);

        SecurityReading reading = WindowsAccessProbe.Convert(SecuredKind.Folder, bytes).Value!;

        Assert.AreEqual(FakeAccess.Administrators, reading.Owner);
        Assert.IsTrue(reading.HasList);
        CollectionAssert.AreEqual(
            new[]
            {
                new PermissionEntry(FakeAccess.Everyone, Allows: false, 0x2),
                new PermissionEntry(FakeAccess.Users, Allows: true, 0x1200A9),
                new PermissionEntry(FakeAccess.Users, Allows: true, 0x10000000, InheritOnly: true),
            },
            reading.Entries.ToArray());
    }

    [TestMethod]
    public void ADescriptorWithoutAList_SaysSo_RatherThanLookingEmpty()
    {
        var descriptor = new RawSecurityDescriptor(
            ControlFlags.None, new SecurityIdentifier(FakeAccess.Administrators), group: null, systemAcl: null, discretionaryAcl: null);
        byte[] bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);

        SecurityReading reading = WindowsAccessProbe.Convert(SecuredKind.File, bytes).Value!;

        Assert.IsFalse(reading.HasList);
        Assert.AreEqual(0, reading.Entries.Count);
    }

    [TestMethod]
    public void ADriveLetter_IsToldApartFromSomethingThatIsNotOne()
    {
        char own = Path.GetPathRoot(_folder)![0];

        Assert.IsTrue(Probe.Drive(own).IsOk);
        Assert.AreEqual(ProbeStatus.Failed, Probe.Drive('1').Status);
    }

    [TestMethod]
    public void AMissingRegistryKey_IsNotFound()
    {
        Assert.AreEqual(
            ProbeStatus.NotFound,
            Probe.ReadKey(RegistryRoot.CurrentUser, @"Software\SecReview.Tests\" + Guid.NewGuid().ToString("N")).Status);
    }
}
