using System.Text;
using SecReview.Probing;
using SecReview.Probing.Windows;

namespace SecReview.Tests.Probing;

/// <summary>Reads only files these tests write into their own temporary folder.</summary>
[TestClass]
public sealed class DiskFileProbeTests
{
    private static readonly DiskFileProbe Probe = new();

    private string _folder = string.Empty;

    public TestContext TestContext { get; set; } = null!;

    [TestInitialize]
    public void CreateFolder()
    {
        _folder = Path.Combine(TestContext.TestRunDirectory!, "files-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_folder);
    }

    [TestCleanup]
    public void RemoveFolder() => Directory.Delete(_folder, recursive: true);

    private string Write(string name, byte[] content)
    {
        string path = Path.Combine(_folder, name);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, content);
        return path;
    }

    [TestMethod]
    public void ReadText_ReturnsTheText()
    {
        string path = Write("a.toml", Encoding.UTF8.GetBytes("key = \"värde\"\n"));

        ProbeResult<string> result = Probe.ReadText(path);

        Assert.IsTrue(result.IsOk);
        Assert.AreEqual("key = \"värde\"\n", result.Value);
    }

    [TestMethod]
    public void ReadText_MissingFile_IsNotFound()
    {
        Assert.AreEqual(ProbeStatus.NotFound, Probe.ReadText(Path.Combine(_folder, "none.txt")).Status);
        Assert.AreEqual(ProbeStatus.NotFound, Probe.ReadText(Path.Combine(_folder, "no-folder", "none.txt")).Status);
    }

    [TestMethod]
    public void ReadText_LargerThanTheLimit_Fails_RatherThanReturningPart()
    {
        string path = Write("big.txt", new byte[2049]);

        ProbeResult<string> result = Probe.ReadText(path, maximumBytes: 2048);

        Assert.AreEqual(ProbeStatus.Failed, result.Status);
        StringAssert.Contains(result.Detail, "larger than 2 KB");
    }

    [TestMethod]
    public void ReadText_ExactlyTheLimit_IsRead()
    {
        string path = Write("fits.txt", Encoding.ASCII.GetBytes(new string('x', 2048)));

        Assert.IsTrue(Probe.ReadText(path, maximumBytes: 2048).IsOk);
    }

    [TestMethod]
    public void ReadText_ARelativePath_IsRefused()
    {
        Assert.AreEqual(ProbeStatus.Failed, Probe.ReadText("a.toml").Status);
        Assert.AreEqual(ProbeStatus.Failed, Probe.List("somewhere").Status);
    }

    [TestMethod]
    [DataRow(@"\\server.example\share\file.txt")]
    [DataRow(@"//server.example/share/file.txt")]
    [DataRow(@"\\?\C:\Windows\win.ini")]
    [DataRow(@"\\.\C:\Windows\win.ini")]
    [DataRow(@"C:relative.txt")]
    [DataRow(@"\Windows\win.ini")]
    [DataRow("")]
    public void APathThatIsNotOnADriveOfThisPc_IsRefused_BeforeAnythingIsOpened(string path)
    {
        // A network path would make Windows sign in to that server as the user.
        Assert.IsFalse(DiskFileProbe.IsFullPath(path));
        Assert.AreEqual(ProbeStatus.Failed, Probe.ReadText(path).Status);
        Assert.AreEqual(ProbeStatus.Failed, Probe.List(path).Status);
    }

    [TestMethod]
    public void APathOnADrive_IsAccepted()
    {
        Assert.IsTrue(DiskFileProbe.IsFullPath(@"C:\Users\tester\.ssh\config"));
        Assert.IsTrue(DiskFileProbe.IsFullPath("d:/data/file.txt"));
    }

    [TestMethod]
    public void ReadText_AFolder_IsAFailure_NotAnException()
    {
        Assert.IsFalse(Probe.ReadText(_folder).IsOk);
    }

    [TestMethod]
    public void Decode_HonoursByteOrderMarks()
    {
        byte[] utf8 = [0xEF, 0xBB, 0xBF, .. Encoding.UTF8.GetBytes("é")];
        byte[] utf16 = [0xFF, 0xFE, .. Encoding.Unicode.GetBytes("é")];
        byte[] utf16BigEndian = [0xFE, 0xFF, .. Encoding.BigEndianUnicode.GetBytes("é")];

        Assert.AreEqual("é", DiskFileProbe.Decode(utf8).Value);
        Assert.AreEqual("é", DiskFileProbe.Decode(utf16).Value);
        Assert.AreEqual("é", DiskFileProbe.Decode(utf16BigEndian).Value);
        Assert.AreEqual(string.Empty, DiskFileProbe.Decode([]).Value);
    }

    [TestMethod]
    public void Decode_WhatIsNotText_Fails_RatherThanBeingGuessedAt()
    {
        // A lone 0xE9 is "é" in an old Windows code page but not valid UTF-8.
        Assert.AreEqual(ProbeStatus.Failed, DiskFileProbe.Decode([0x61, 0xE9, 0x62]).Status);
        Assert.AreEqual(ProbeStatus.Failed, DiskFileProbe.Decode([0x61, 0x00, 0x62]).Status);
        Assert.AreEqual(ProbeStatus.Failed, DiskFileProbe.Decode([0xFF, 0xFE, 0x61]).Status, "half a UTF-16 character");
    }

    [TestMethod]
    public void List_ReturnsFilesAndFolders_SortedByName()
    {
        Write("b.txt", [1, 2, 3]);
        Write("A.txt", []);
        Write(Path.Combine("sub", "inner.txt"), [1]);

        ProbeResult<IReadOnlyList<FileEntry>> result = Probe.List(_folder);

        Assert.IsTrue(result.IsOk);
        CollectionAssert.AreEqual(new[] { "A.txt", "b.txt", "sub" }, result.Value!.Select(e => e.Name).ToArray());
        Assert.AreEqual(3, result.Value![1].Length);
        Assert.IsTrue(result.Value[2].IsDirectory);
        Assert.IsFalse(result.Value[2].IsLink);
    }

    [TestMethod]
    public void List_MissingFolder_IsNotFound()
    {
        Assert.AreEqual(ProbeStatus.NotFound, Probe.List(Path.Combine(_folder, "none")).Status);
    }
}
