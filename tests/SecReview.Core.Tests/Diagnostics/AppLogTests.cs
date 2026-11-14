using SecReview.Checks;
using SecReview.Diagnostics;

namespace SecReview.Tests.Diagnostics;

/// <summary>The local log. Every name and path here is made up.</summary>
[TestClass]
public sealed class AppLogTests
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

    private AppLog NewLog() => new(_folder, new PrivacyFilter(@"C:\Users\alice", "alice", "DESKTOP-EXAMPLE"), TimeProvider.System);

    [TestMethod]
    public void ALine_IsWritten_WithoutTheUsersName()
    {
        AppLog log = NewLog();

        log.Info(@"Read C:\Users\alice\made-up.txt");

        string text = File.ReadAllText(log.Path);
        StringAssert.Contains(text, "INFO");
        StringAssert.Contains(text, "made-up.txt");
        Assert.IsFalse(text.Contains("alice", StringComparison.OrdinalIgnoreCase));
    }

    [TestMethod]
    public void ALineWrittenWhileAnotherProcessHoldsTheFile_IsWrittenOnceItLetsGo()
    {
        // #53: a reader that lets nobody write (as File.ReadAllBytes opens it) held the file
        // for a moment, and the line written meanwhile was lost.
        AppLog log = NewLog();
        log.Info("first");
        var held = new FileStream(log.Path, FileMode.Open, FileAccess.Read, FileShare.Read);
        Task release = Task.Run(async () =>
        {
            await Task.Delay(30);
            held.Dispose();
        });

        log.Info("written while held");
        release.Wait();

        StringAssert.Contains(File.ReadAllText(log.Path), "written while held");
    }

    [TestMethod]
    public void AFileHeldForGood_LosesTheLine_ButNeverThrowsOrHangs()
    {
        AppLog log = NewLog();
        log.Info("first");
        using var held = new FileStream(log.Path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var timer = System.Diagnostics.Stopwatch.StartNew();

        log.Info("lost");

        Assert.IsTrue(timer.Elapsed < TimeSpan.FromSeconds(2), $"logging waited {timer.Elapsed}");
    }
}
