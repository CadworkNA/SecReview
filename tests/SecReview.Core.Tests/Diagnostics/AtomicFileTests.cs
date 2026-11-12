using SecReview.Diagnostics;

namespace SecReview.Tests.Diagnostics;

[TestClass]
public sealed class AtomicFileTests
{
    private string _folder = string.Empty;

    [TestInitialize]
    public void CreateFolder() => _folder = Path.Combine(Path.GetTempPath(), "SecReview.Tests." + Guid.NewGuid().ToString("N"));

    [TestCleanup]
    public void DeleteFolder()
    {
        if (Directory.Exists(_folder))
        {
            Directory.Delete(_folder, recursive: true);
        }
    }

    [TestMethod]
    public void WhatIsWritten_IsReadBack_AndNothingElseIsLeft()
    {
        string file = Path.Combine(_folder, "made-up.json");

        AtomicFile.Write(file, "first"u8);
        AtomicFile.Write(file, "second"u8);

        CollectionAssert.AreEqual("second"u8.ToArray(), AtomicFile.Read(file));
        Assert.AreEqual(1, Directory.GetFiles(_folder).Length);
    }

    [TestMethod]
    public void AFileBeingWritten_IsReplacedOnceItsWriterLetsGo()
    {
        string file = Path.Combine(_folder, "made-up.json");
        AtomicFile.Write(file, "first"u8);

        // Held for a moment by another program: the other SecReview process reading it, or a scanner.
        var held = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.None);
        Task release = Task.Run(async () =>
        {
            await Task.Delay(60);
            held.Dispose();
        });

        AtomicFile.Write(file, "second"u8);
        release.Wait();

        CollectionAssert.AreEqual("second"u8.ToArray(), AtomicFile.Read(file));
    }
}
