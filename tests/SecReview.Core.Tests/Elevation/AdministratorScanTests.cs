using System.IO.Pipes;
using System.Security.Principal;
using SecReview.Catalogue;
using SecReview.Checks;
using SecReview.Checks.BuiltIn;
using SecReview.CommandLine;
using SecReview.Elevation;
using SecReview.Scanning;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.Elevation;

[TestClass]
public sealed class AdministratorScanTests
{
    private static readonly IReadOnlyList<ICheck> Checks = CheckCatalogue.Checks;
    private static readonly CheckTexts Texts = CheckCatalogue.Texts;

    private static readonly int AdministratorChecks =
        Checks.Count(check => CheckRunner.IsIncluded(check.Definition, CheckSelection.AdministratorOnly));

    /// <summary>Stands in for the Windows prompt and the helper it starts: runs something against the pipe from this very process.</summary>
    private sealed class Launcher(Func<string, Task>? helper, int? processId = null, bool declined = false, Exception? fails = null) : IElevatedLauncher
    {
        public string? PipeName { get; private set; }

        public Task Helper { get; private set; } = Task.CompletedTask;

        public ElevatedProcess? Start(string pipeName)
        {
            PipeName = pipeName;
            if (fails is not null)
            {
                throw fails;
            }

            if (declined)
            {
                return null;
            }

            Helper = Task.Run(() => helper!(pipeName));
            return new ElevatedProcess(processId ?? Environment.ProcessId);
        }
    }

    /// <summary>The real helper code, with made-up readings, as if it had administrator rights.</summary>
    private static Task<bool> RealHelper(string pipeName) =>
        ElevatedHelper.RunAsync(pipeName, new FakeProbes().Build(), isElevated: true, TimeProvider.System, Checks, Texts);

    /// <summary>Something that connects to the pipe and writes whatever it likes.</summary>
    private static Func<string, Task> Writes(byte[] bytes) => async pipeName =>
    {
        using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.Out, PipeOptions.Asynchronous, TokenImpersonationLevel.Anonymous);
        await pipe.ConnectAsync(10_000);
        try
        {
            await pipe.WriteAsync(bytes);
            await pipe.FlushAsync();
        }
        catch (IOException)
        {
            // The window hung up: that is the point of some of these tests.
        }
    };

    [TestMethod]
    public void APipeName_IsThePrefixAnd32RandomHexDigits_AndNothingElseIsOne()
    {
        string name = ElevationPipe.NewName();

        Assert.IsTrue(ElevationPipe.IsValidName(name));
        Assert.AreEqual(ElevationPipe.Prefix.Length + 32, name.Length);
        Assert.AreNotEqual(name, ElevationPipe.NewName());

        foreach (string? bad in new[]
        {
            null, "", "SecReview.Elev.", name[..^1], name + "0", name.ToUpperInvariant(), ElevationPipe.Prefix + new string('g', 32),
            @"\\.\pipe\" + name, @"..\" + name[3..], "secreview.elev." + name[ElevationPipe.Prefix.Length..], " " + name[1..],
            ElevationPipe.Prefix + new string('0', 31) + "/", "Other.Pipe." + new string('0', 32),
        })
        {
            Assert.IsFalse(ElevationPipe.IsValidName(bad), bad);
        }
    }

    [TestMethod]
    public void TheHelpersCommand_TakesExactlyAPipeNameOfOurs()
    {
        string name = ElevationPipe.NewName();

        Assert.AreEqual(new ElevatedScanCommand(name), CliArguments.Parse(["--elevated-scan", "--pipe", name]));

        foreach (string[] bad in new[]
        {
            new[] { "--elevated-scan" },
            ["--elevated-scan", "--pipe"],
            ["--elevated-scan", name],
            ["--elevated-scan", "--pipe", "anything"],
            ["--elevated-scan", "--pipe", @"\\server\pipe\x"],
            ["--elevated-scan", "--pipe", name, "--report"],
            ["--elevated-scan", "--pipe", name, @"C:\file"],
            ["--elevated-scan", "--Pipe", name],
            ["--pipe", name, "--elevated-scan"],
        })
        {
            Assert.IsInstanceOfType<InvalidCommand>(CliArguments.Parse(bad), string.Join(' ', bad));
        }
    }

    [TestMethod]
    public async Task TheHelpersAnswer_ComesBackAsTheResultsOfTheAdministratorChecks()
    {
        var launcher = new Launcher(RealHelper);

        AdministratorScanResult result = await AdministratorScan.RunAsync(launcher, Checks, Texts, TimeSpan.FromSeconds(30));
        await launcher.Helper;

        Assert.AreEqual(AdministratorScanOutcome.Completed, result.Outcome, result.Problem);
        Assert.IsTrue(ElevationPipe.IsValidName(launcher.PipeName));
        Assert.AreEqual(AdministratorChecks, result.Scan!.Checks.Count);
        Assert.IsTrue(AdministratorChecks > 5, "the catalogue has administrator checks");
        Assert.IsTrue(result.Scan.Elevated);
        Assert.IsTrue(result.Scan.Checks.All(check => check.Result.Elevated));
        Assert.IsTrue(result.Scan.Checks.All(check => check.Definition.Scope == CheckScope.Machine && check.Definition.NeedsAdmin != AdminNeed.No));
        Assert.IsTrue(
            result.Scan.Checks.All(check => check.Result.Outcome.Status != CheckStatus.NeedsAdmin),
            "with administrator rights no check still asks for them");
    }

    [TestMethod]
    public async Task SayingNoAtThePrompt_IsNotAnError()
    {
        AdministratorScanResult result = await AdministratorScan.RunAsync(new Launcher(null, declined: true), Checks, Texts);

        Assert.AreEqual(AdministratorScanOutcome.Cancelled, result.Outcome);
        Assert.IsNull(result.Scan);
        Assert.IsNull(result.Problem);
    }

    [TestMethod]
    public async Task AHelperThatCannotBeStarted_IsAFailureWithTheReason()
    {
        var launcher = new Launcher(null, fails: new InvalidOperationException("Windows did not start the helper."));

        AdministratorScanResult result = await AdministratorScan.RunAsync(launcher, Checks, Texts);

        Assert.AreEqual(AdministratorScanOutcome.Failed, result.Outcome);
        Assert.AreEqual("The administrator checks could not be run: Windows did not start the helper.", result.Problem);
    }

    [TestMethod]
    public async Task AnotherProcessOnThePipe_IsHungUpOn_HoweverGoodItsAnswerLooks()
    {
        // What a program of the same user would try: answer in the helper's place, with passes.
        // Here the "stranger" is this test process, and the helper is said to be process 4.
        byte[] forged = ResultsStore.ToBytes(new ScanResult(
            [.. Checks.Where(check => CheckRunner.IsIncluded(check.Definition, CheckSelection.AdministratorOnly)).Select(check => new ScannedCheck(
                check.Definition,
                Texts[check.Definition.Id],
                new CheckResult(check.Definition.Id, CheckOutcome.Pass("All fine, trust me."), DateTimeOffset.UtcNow, Elevated: true, TimeSpan.Zero)))],
            DateTimeOffset.UtcNow,
            Elevated: true));
        var launcher = new Launcher(Writes(forged), processId: 4);

        AdministratorScanResult result = await AdministratorScan.RunAsync(launcher, Checks, Texts, TimeSpan.FromSeconds(2));
        await launcher.Helper;

        Assert.AreEqual(AdministratorScanOutcome.Failed, result.Outcome);
        Assert.AreEqual("The administrator checks did not answer in time.", result.Problem);
        Assert.IsNull(result.Scan);

        // The same answer from the process that was started is taken: the difference is who sent it.
        var genuine = new Launcher(Writes(forged));
        AdministratorScanResult taken = await AdministratorScan.RunAsync(genuine, Checks, Texts, TimeSpan.FromSeconds(30));
        await genuine.Helper;
        Assert.AreEqual(AdministratorScanOutcome.Completed, taken.Outcome, taken.Problem);
    }

    [TestMethod]
    public async Task AnAnswerThatIsTooLarge_IsNotRead()
    {
        var launcher = new Launcher(Writes(new byte[ElevationPipe.MaximumBytes + 100_000]));

        AdministratorScanResult result = await AdministratorScan.RunAsync(launcher, Checks, Texts, TimeSpan.FromSeconds(30));
        await launcher.Helper;

        Assert.AreEqual(AdministratorScanOutcome.Failed, result.Outcome);
        Assert.AreEqual("The administrator checks sent more than they should; their answer was not used.", result.Problem);
    }

    [TestMethod]
    public async Task AnAnswerThatIsNotResults_OrNotTheseChecks_IsNotUsed()
    {
        const string Unusable = "The administrator checks' answer could not be used.";

        // Not a document at all.
        var garbage = new Launcher(Writes("not results"u8.ToArray()));
        Assert.AreEqual(Unusable, (await AdministratorScan.RunAsync(garbage, Checks, Texts, TimeSpan.FromSeconds(30))).Problem);
        await garbage.Helper;

        // Nothing at all.
        var empty = new Launcher(Writes([]));
        Assert.AreEqual(Unusable, (await AdministratorScan.RunAsync(empty, Checks, Texts, TimeSpan.FromSeconds(30))).Problem);
        await empty.Helper;

        // A well-formed answer about a check that is not an administrator check: an ordinary
        // result must not come in through this door.
        var ordinary = new AutomaticLogonCheck();
        Assert.AreEqual(AdminNeed.No, ordinary.Definition.NeedsAdmin);
        byte[] wrongChecks = ResultsStore.ToBytes(new ScanResult(
            [new ScannedCheck(ordinary.Definition, Texts[ordinary.Definition.Id], new CheckResult(ordinary.Definition.Id, CheckOutcome.Pass("Off."), DateTimeOffset.UtcNow, true, TimeSpan.Zero))],
            DateTimeOffset.UtcNow,
            Elevated: true));
        var other = new Launcher(Writes(wrongChecks));
        Assert.AreEqual(Unusable, (await AdministratorScan.RunAsync(other, Checks, Texts, TimeSpan.FromSeconds(30))).Problem);
        await other.Helper;
    }

    [TestMethod]
    public async Task AHelperThatNeverAnswers_EndsInAFailure_NotAHang()
    {
        var launcher = new Launcher(_ => Task.CompletedTask);

        AdministratorScanResult result = await AdministratorScan.RunAsync(launcher, Checks, Texts, TimeSpan.FromSeconds(1));

        Assert.AreEqual(AdministratorScanOutcome.Failed, result.Outcome);
        Assert.AreEqual("The administrator checks did not answer in time.", result.Problem);
    }

    [TestMethod]
    public async Task TheHelper_RefusesANameThatIsNotOurs_AndGivesUpWhenNobodyListens()
    {
        Assert.IsFalse(await ElevatedHelper.RunAsync("some.other.pipe", new FakeProbes().Build(), true, TimeProvider.System, Checks, Texts));
        Assert.IsFalse(await ElevatedHelper.RunAsync(@"\\server\pipe\x", new FakeProbes().Build(), true, TimeProvider.System, Checks, Texts));

        // A well-formed name with no window behind it.
        Assert.IsFalse(await ElevatedHelper.RunAsync(
            ElevationPipe.NewName(), new FakeProbes().Build(), true, TimeProvider.System, Checks, Texts, connectTimeout: TimeSpan.FromMilliseconds(300)));
    }

    [TestMethod]
    public async Task WithoutAdministratorRights_TheHelperStillAnswers_AndSaysWhatItCouldNotRead()
    {
        // Started by hand without the prompt: harmless, and honest about it.
        var launcher = new Launcher(name => ElevatedHelper.RunAsync(name, new FakeProbes().Build(), isElevated: false, TimeProvider.System, Checks, Texts));

        AdministratorScanResult result = await AdministratorScan.RunAsync(launcher, Checks, Texts, TimeSpan.FromSeconds(30));
        await launcher.Helper;

        Assert.AreEqual(AdministratorScanOutcome.Completed, result.Outcome, result.Problem);
        Assert.IsTrue(result.Scan!.Checks.Any(check => check.Result.Outcome.Status == CheckStatus.NeedsAdmin));
        Assert.IsFalse(result.Scan.Elevated);
    }

    [TestMethod]
    [DataRow(@"C:\Program Files\SecReview", true, null)]
    [DataRow(@"C:\Program Files\SecReview\", true, null)]
    [DataRow(@"c:\program files\SecReview", true, null)]
    [DataRow(@"C:\Program Files (x86)\SecReview", true, null)]
    [DataRow(@"C:\Program Files\Vendor\SecReview", true, null)]
    [DataRow(@"C:\Program Files\SecReview", false, "The administrator checks cannot be run: a part of SecReview is missing. Install it again.")]
    [DataRow(@"C:\Users\tester\Downloads\SecReview", true, "The administrator checks can be run once SecReview is installed for everyone (in Program Files).")]
    [DataRow(@"C:\Program Files Evil\SecReview", true, "The administrator checks can be run once SecReview is installed for everyone (in Program Files).")]
    [DataRow(@"C:\Program Files", true, "The administrator checks can be run once SecReview is installed for everyone (in Program Files).")]
    [DataRow(@"C:\Program Files\..\Users\tester\SecReview", true, "The administrator checks can be run once SecReview is installed for everyone (in Program Files).")]
    [DataRow(@"D:\source\SecReview\artifacts\stage", true, "The administrator checks can be run once SecReview is installed for everyone (in Program Files).")]
    public void TheHelperIsOnlyStartedFromAFolderOrdinaryUsersCannotWriteTo(string appFolder, bool helperExists, string? expected)
    {
        string[] protectedFolders = [@"C:\Program Files", @"C:\Program Files (x86)", ""];

        string? why = AdministratorScan.WhyUnavailable(appFolder, protectedFolders, path =>
        {
            Assert.IsTrue(path.EndsWith(@"\SecReviewCli.exe", StringComparison.Ordinal), path);
            return helperExists;
        });

        Assert.AreEqual(expected, why);
    }

    [TestMethod]
    public void TheRealLauncher_RefusesAnythingButOurPipeNameAndAFullPath()
    {
        Assert.ThrowsExactly<InvalidOperationException>(() => new WindowsElevatedLauncher(@"C:\Program Files\SecReview\SecReviewCli.exe").Start("x & calc.exe"));
        Assert.ThrowsExactly<InvalidOperationException>(() => new WindowsElevatedLauncher("SecReviewCli.exe").Start(ElevationPipe.NewName()));
    }
}
