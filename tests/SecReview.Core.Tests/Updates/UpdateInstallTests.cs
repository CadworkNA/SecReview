using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using SecReview.Elevation;
using SecReview.Updates;
using SecReview.Updates.Windows;

namespace SecReview.Tests.Updates;

[TestClass]
public sealed class UpdateInstallTests
{
    private const string ManifestAddress = "https://github.com/made-up/secreview/releases/latest/download/latest.json";
    private const string SetupAddress = "https://github.com/made-up/secreview/releases/download/v1.4.0/SecReview-1.4.0-setup.exe";
    private const string Subject = "CN=Made Up Software Inc., O=Made Up Software Inc., L=Montreal, S=Quebec, C=CA";
    private const string Identity = "1.3.6.1.4.1.311.97.1.2.3.4";
    private const string Root = "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF";

    private static readonly DateTimeOffset Now = new(2026, 11, 11, 9, 0, 0, TimeSpan.Zero);
    private static readonly UpdateSource Source = new(ManifestAddress);
    private static readonly PublisherIdentity Publisher = new(Subject, Identity, Root);
    private static readonly byte[] Setup = Encoding.UTF8.GetBytes("made-up setup program " + new string('x', 5000));

    private string _folder = string.Empty;

    [TestInitialize]
    public void CreateFolder()
    {
        _folder = Path.Combine(Path.GetTempPath(), "SecReview.Tests." + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_folder);
    }

    [TestCleanup]
    public void DeleteFolder()
    {
        if (Directory.Exists(_folder))
        {
            Directory.Delete(_folder, recursive: true);
        }
    }

    private static InstallerSignature Good(string version = "1.4.0.0", string product = "1.4.0") =>
        new(true, true, Subject, ["1.3.6.1.5.5.7.3.3", Identity], Root, version, product);

    private static byte[] Manifest(string version = "1.4.0", byte[]? setup = null) => new UpdateManifest(
        version, new Uri(SetupAddress), Convert.ToHexStringLower(SHA256.HashData(setup ?? Setup)), Now.AddDays(-2), "Two new checks.").ToBytes();

    /// <summary>Plays both ends: the window's side for real, and the helper's real code with made-up Windows parts.</summary>
    private async Task<(UpdateInstallOutcome Outcome, string? Problem, List<UpdateProgress> Seen, Host Host)> Install(
        Downloader downloader,
        Host? host = null,
        PublisherIdentity? publisher = null,
        UpdatePolicy policy = default,
        string installed = "1.3.0",
        UpdateSource? source = null)
    {
        host ??= new Host(_folder);
        var seen = new List<UpdateProgress>();
        var launcher = new Launcher(pipeName => UpdateApplier.RunAsync(
            pipeName, source ?? Source, publisher ?? Publisher, policy, installed, downloader, host, new Clock(Now)));

        (UpdateInstallOutcome outcome, string? problem) = await UpdateInstall.RunAsync(launcher, seen.Add, alsoThisUser: true);
        await launcher.Helper;
        return (outcome, problem, seen, host);
    }

    [TestMethod]
    public async Task AGoodUpdate_IsDownloadedCheckedAndStarted_SilentlyAndWithARelaunch()
    {
        var downloader = new Downloader { Manifest = Manifest(), Setup = Setup };

        (UpdateInstallOutcome outcome, string? problem, List<UpdateProgress> seen, Host host) = await Install(downloader);

        Assert.AreEqual(UpdateInstallOutcome.Installing, outcome, problem);
        CollectionAssert.AreEqual(
            new[] { UpdateStage.Checking, UpdateStage.Verifying, UpdateStage.Installing },
            seen.Select(step => step.Stage).Where(stage => stage != UpdateStage.Downloading).ToArray());

        (string path, IReadOnlyList<string> arguments) = host.Started.Single();
        Assert.AreEqual(Path.Combine(_folder, "work", UpdateApplier.SetupFileName), path);
        CollectionAssert.AreEqual(new[] { "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/RELAUNCH=1" }, arguments.ToArray());
        CollectionAssert.AreEqual(Setup, File.ReadAllBytes(path), "what was checked is what was started");
        CollectionAssert.AreEqual(new[] { new Uri(ManifestAddress), new Uri(SetupAddress) }, downloader.Asked);
    }

    [TestMethod]
    public async Task WithAnotherAccountsAdministratorRights_SecReviewIsNotOpenedAgainBySetup()
    {
        var host = new Host(_folder) { SameUser = false };

        (UpdateInstallOutcome outcome, _, _, _) = await Install(new Downloader { Manifest = Manifest(), Setup = Setup }, host);

        Assert.AreEqual(UpdateInstallOutcome.Installing, outcome);
        CollectionAssert.AreEqual(new[] { "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART" }, host.Started.Single().Arguments.ToArray());
    }

    [TestMethod]
    public async Task AFileThatIsNotTheOneAnnounced_IsNotStarted()
    {
        byte[] other = [.. Setup, 1];
        var downloader = new Downloader { Manifest = Manifest(), Setup = other };

        (UpdateInstallOutcome outcome, string? problem, _, Host host) = await Install(downloader);

        Assert.AreEqual(UpdateInstallOutcome.Failed, outcome);
        StringAssert.Contains(problem, "not the file the server announced");
        Assert.AreEqual(0, host.Started.Count);
        Assert.AreEqual(0, host.Inspected, "a file with the wrong checksum is not even looked at further");
        Assert.IsFalse(File.Exists(Path.Combine(_folder, "work", UpdateApplier.SetupFileName)), "what was not installed does not stay");
    }

    [TestMethod]
    [DataRow("not validly signed")]
    [DataRow("no timestamp")]
    [DataRow("another publisher")]
    [DataRow("another identity")]
    [DataRow("another root")]
    [DataRow("an older file")]
    [DataRow("a pre-release passed off as the release")]
    [DataRow("another version")]
    public async Task ASetupProgramThatIsNotOursOrNotTheAnnouncedVersion_IsNotStarted(string what)
    {
        InstallerSignature signature = what switch
        {
            "not validly signed" => Good() with { Valid = false, Problem = "Windows answered 0x800B0100" },
            "no timestamp" => Good() with { Timestamped = false },
            "another publisher" => Good() with { Subject = "CN=Somebody Else, O=Somebody Else, C=CA" },
            "another identity" => Good() with { KeyUsages = ["1.3.6.1.5.5.7.3.3", "1.3.6.1.4.1.311.97.9.9.9.9"] },

            // The right name and identifier, under a root somebody added to their own trusted roots.
            "another root" => Good() with { RootSha256 = new string('A', 64) },
            "an older file" => Good("1.2.0.0", "1.2.0"),

            // Signed by us, same four numbers, but it is the beta.
            "a pre-release passed off as the release" => Good("1.4.0.0", "1.4.0-beta.1"),
            _ => Good("1.5.0.0", "1.5.0"),
        };
        var host = new Host(_folder) { Signature = signature };

        (UpdateInstallOutcome outcome, string? problem, _, _) = await Install(new Downloader { Manifest = Manifest(), Setup = Setup }, host);

        Assert.AreEqual(UpdateInstallOutcome.Failed, outcome);
        StringAssert.Contains(problem, "Nothing was installed");
        Assert.AreEqual(0, host.Started.Count, what);
        Assert.IsFalse(File.Exists(Path.Combine(_folder, "work", UpdateApplier.SetupFileName)), "what was not installed does not stay");
    }

    [TestMethod]
    [DataRow("9.9.9+/../../../../ProgramData/made-up/a")]
    [DataRow(@"9.9.9+\..\..\made-up")]
    [DataRow("9.9.9+build")]
    [DataRow("9.9.9:stream")]
    [DataRow(" 9.9.9")]
    [DataRow("9.9.9 ")]
    [DataRow("V9.9.9")]
    [DataRow("9.9.9-rc/1")]
    [DataRow("9.9")]
    public async Task AVersionThatIsNotPlainlyAVersion_IsRefused_AndNothingIsWrittenAnywhere(string version)
    {
        string json = $$"""{"version":{{System.Text.Json.JsonSerializer.Serialize(version)}},"url":"{{SetupAddress}}","sha256":"{{new string('a', 64)}}","published":"2026-11-01T10:00:00Z","notes":""}""";
        var downloader = new Downloader { Manifest = Encoding.UTF8.GetBytes(json), Setup = Setup };

        (UpdateInstallOutcome outcome, string? problem, _, Host host) = await Install(downloader);

        Assert.AreEqual(UpdateInstallOutcome.Failed, outcome);
        StringAssert.Contains(problem, "names no proper version");
        Assert.AreEqual(1, downloader.Asked.Count, "the setup program was never fetched");
        Assert.AreEqual(0, host.Started.Count);
        Assert.IsFalse(Directory.Exists(Path.Combine(_folder, "work")), "no folder was even made");
        Assert.IsFalse(UpdateRules.IsReleaseVersion(version));
        Assert.IsFalse(UpdateRules.IsNewer(version, "1.3.0"));
    }

    [TestMethod]
    public void AReleaseVersion_IsThreeNumbersAndPerhapsAPreReleasePart()
    {
        foreach (string good in new[] { "0.0.0", "1.4.0", "10.20.30", "1.4.0-rc.1", "0.0.0-ci.12", "0.0.0-dev", "1.0.0-beta-2" })
        {
            Assert.IsTrue(UpdateRules.IsReleaseVersion(good), good);
        }

        foreach (string? bad in new[] { null, "", "1", "1.4", "1.4.0.0", "01.4.0", "1.4.0-", "1.4.0\n", "1.4.0-rc 1", "v1.4.0", "1.4.0+1", new string('1', 70) + ".0.0" })
        {
            Assert.IsFalse(UpdateRules.IsReleaseVersion(bad), bad);
        }
    }

    [TestMethod]
    public void ThePublisherRule_ComparesTheWholeSubject_AndNeedsTheIdentityWhenThereIsOne()
    {
        Assert.IsNull(UpdateApplier.Refusal(Good(), Publisher, "1.4.0", "1.3.0"));
        Assert.IsNull(UpdateApplier.Refusal(Good() with { KeyUsages = [] }, Publisher with { IdentityOid = string.Empty }, "1.4.0", "1.3.0"), "a publisher without such an identifier");
        Assert.IsNull(UpdateApplier.Refusal(Good() with { RootSha256 = Root.ToLowerInvariant() }, Publisher, "1.4.0", "1.3.0"), "a hash is the same in either case");
        Assert.IsNotNull(UpdateApplier.Refusal(Good() with { RootSha256 = string.Empty }, Publisher, "1.4.0", "1.3.0"));
        Assert.IsNotNull(UpdateApplier.Refusal(Good(), Publisher with { RootSha256 = string.Empty }, "1.4.0", "1.3.0"), "a build that names no root installs nothing");

        Assert.IsNotNull(UpdateApplier.Refusal(Good() with { Subject = Subject.ToUpperInvariant() }, Publisher, "1.4.0", "1.3.0"));
        Assert.IsNotNull(UpdateApplier.Refusal(Good() with { Subject = Subject + ", OU=Extra" }, Publisher, "1.4.0", "1.3.0"));
        Assert.IsNotNull(UpdateApplier.Refusal(Good() with { KeyUsages = [] }, Publisher, "1.4.0", "1.3.0"));
        Assert.IsNotNull(UpdateApplier.Refusal(Good(), new PublisherIdentity(string.Empty, string.Empty, string.Empty), "1.4.0", "1.3.0"), "a build that names no publisher installs nothing");

        // The same version again, or an older one, even when properly signed.
        Assert.IsNotNull(UpdateApplier.Refusal(Good("1.3.0.0", "1.3.0"), Publisher, "1.3.0", "1.3.0"));
        Assert.IsNotNull(UpdateApplier.Refusal(Good("1.2.0.0", "1.2.0"), Publisher, "1.2.0", "1.3.0"));
        Assert.IsNull(UpdateApplier.Refusal(Good("1.4.0.0", "1.4.0-rc.2"), Publisher, "1.4.0-rc.2", "1.4.0-rc.1"));
        Assert.IsNotNull(UpdateApplier.Refusal(Good("1.4.0.0", "1.4.0-rc.1"), Publisher, "1.4.0-rc.2", "1.4.0-rc.1"), "rc.1 again, announced as rc.2");
    }

    [TestMethod]
    public async Task NothingIsDownloaded_WhenThereIsNothingNewer_OrTheBuildOrTheOrganisationSaysNo()
    {
        var same = new Downloader { Manifest = Manifest("1.3.0"), Setup = Setup };
        (UpdateInstallOutcome outcome, string? problem, _, _) = await Install(same);
        Assert.AreEqual(UpdateInstallOutcome.Failed, outcome);
        StringAssert.Contains(problem, "newest version already");
        Assert.AreEqual(1, same.Asked.Count, "only the list of versions was fetched");

        foreach ((string reason, Func<Downloader, Task<(UpdateInstallOutcome, string?, List<UpdateProgress>, Host)>> run) in new (string, Func<Downloader, Task<(UpdateInstallOutcome, string?, List<UpdateProgress>, Host)>>)[]
        {
            ("does not install updates", d => Install(d, publisher: new PublisherIdentity(string.Empty, string.Empty, string.Empty))),
            ("does not install updates", d => Install(d, source: new UpdateSource(null))),
            ("organisation", d => Install(d, policy: new UpdatePolicy(NoUpdateCheck: false, NoSelfUpdate: true))),
            ("organisation", d => Install(d, policy: new UpdatePolicy(NoUpdateCheck: true, NoSelfUpdate: false))),
            ("administrator rights", d => Install(d, new Host(_folder) { Elevated = false })),
        })
        {
            var downloader = new Downloader { Manifest = Manifest(), Setup = Setup };
            (UpdateInstallOutcome refused, string? why, _, Host host) = await run(downloader);
            Assert.AreEqual(UpdateInstallOutcome.Failed, refused, reason);
            StringAssert.Contains(why, reason);
            Assert.AreEqual(0, downloader.Asked.Count, $"{reason}: nothing may be fetched");
            Assert.AreEqual(0, host.Started.Count);
        }
    }

    [TestMethod]
    public async Task ADownloadThatFails_SaysWhy()
    {
        (UpdateInstallOutcome outcome, string? problem, _, Host host) = await Install(new Downloader { Manifest = Manifest(), Failure = "the connection broke off" });

        Assert.AreEqual(UpdateInstallOutcome.Failed, outcome);
        Assert.AreEqual("The update could not be downloaded: the connection broke off.", problem);
        Assert.AreEqual(0, host.Started.Count);

        (outcome, problem, _, _) = await Install(new Downloader { ManifestFailure = "the server could not be reached" });
        Assert.AreEqual(UpdateInstallOutcome.Failed, outcome);
        StringAssert.Contains(problem, "the server could not be reached");
    }

    [TestMethod]
    public async Task SayingNoAtTheWindowsPrompt_ChangesNothing()
    {
        (UpdateInstallOutcome outcome, string? problem) = await UpdateInstall.RunAsync(new Launcher(null, declined: true), _ => { }, alsoThisUser: true);

        Assert.AreEqual(UpdateInstallOutcome.Cancelled, outcome);
        Assert.IsNull(problem);
    }

    [TestMethod]
    public async Task AHelperThatStopsHalfway_OrTalksNonsense_IsAFailure_NotAnInstall()
    {
        static Func<string, Task> Writes(string text) => async pipeName =>
        {
            using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.Out, PipeOptions.Asynchronous, System.Security.Principal.TokenImpersonationLevel.Anonymous);
            await pipe.ConnectAsync(10_000);
            try
            {
                await pipe.WriteAsync(Encoding.UTF8.GetBytes(text));
                await pipe.FlushAsync();
            }
            catch (IOException)
            {
                // The window hung up.
            }
        };

        foreach (string sent in new[] { string.Empty, "1|0|0|\n2|10|100|\n", "nonsense\n", "4|0|0|", new string('4', 5000) + "\n", "9|0|0|\n" })
        {
            var launcher = new Launcher(Writes(sent));
            (UpdateInstallOutcome outcome, string? problem) = await UpdateInstall.RunAsync(launcher, _ => { }, alsoThisUser: true);
            await launcher.Helper;
            Assert.AreEqual(UpdateInstallOutcome.Failed, outcome, sent.Length > 40 ? "a long line" : sent);
            Assert.IsNotNull(problem);
        }

        var flood = new Launcher(Writes(string.Concat(Enumerable.Repeat("2|1|2|\n", 20_000))));
        (UpdateInstallOutcome tooMuch, string? why) = await UpdateInstall.RunAsync(flood, _ => { }, alsoThisUser: true);
        await flood.Helper;
        Assert.AreEqual(UpdateInstallOutcome.Failed, tooMuch);
        StringAssert.Contains(why, "more than it should");
    }

    [TestMethod]
    public void AProgressLine_SurvivesTheTrip_AndIsOnlyEverPlainText()
    {
        var step = new UpdateProgress(UpdateStage.Downloading, 1234, 5678);
        Assert.AreEqual(step, UpdateProgress.FromLine(step.ToLine()));

        var failed = new UpdateProgress(UpdateStage.Failed, Problem: "It broke | here.\nSecond line");
        UpdateProgress read = UpdateProgress.FromLine(failed.ToLine())!;
        Assert.AreEqual("It broke | here. Second line", read.Problem);
        Assert.IsFalse(failed.ToLine().Contains('\n'));

        Assert.IsNull(UpdateProgress.FromLine(null));
        Assert.IsNull(UpdateProgress.FromLine("0|0|0|"));
        Assert.IsNull(UpdateProgress.FromLine("2|-1|0|"));
        Assert.IsNull(UpdateProgress.FromLine("2|1|"));
        Assert.IsNull(UpdateProgress.FromLine(new string('x', UpdateProgress.MaximumLineLength + 1)));
        Assert.AreEqual("ab", UpdateProgress.FromLine("5|0|0|a\u0007b")!.Problem);
    }

    [TestMethod]
    public async Task APipeNameThatIsNotOurs_IsRefusedByTheHelper()
    {
        var host = new Host(_folder);
        var downloader = new Downloader { Manifest = Manifest(), Setup = Setup };

        Assert.IsFalse(await UpdateApplier.RunAsync(@"\\.\pipe\somebody-elses", Source, Publisher, default, "1.3.0", downloader, host, new Clock(Now)));
        Assert.IsFalse(await UpdateApplier.RunAsync("SecReview.Elev.short", Source, Publisher, default, "1.3.0", downloader, host, new Clock(Now)));
        Assert.AreEqual(0, downloader.Asked.Count);
    }

    [TestMethod]
    [SupportedOSPlatform("windows10.0.19041")]
    public void WindowsSaysWhoSignedAFile_AndThatAnUnsignedOneIsNot()
    {
        // A program Microsoft signs and timestamps, present wherever these tests run.
        string dotnet = Path.Combine(
            Environment.GetEnvironmentVariable("DOTNET_ROOT") ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet"), "dotnet.exe");
        if (!File.Exists(dotnet))
        {
            Assert.Inconclusive("dotnet.exe is not where it is expected.");
        }

        var host = new WindowsUpdateHost(checkRevocation: false);

        InstallerSignature signed = host.Inspect(dotnet);
        Assert.IsTrue(signed.Valid, signed.Problem);
        Assert.IsTrue(signed.Timestamped);
        StringAssert.Contains(signed.Subject, "O=Microsoft Corporation");
        Assert.IsTrue(signed.KeyUsages.Contains("1.3.6.1.5.5.7.3.3"), "signed for code signing");
        Assert.AreEqual(64, signed.RootSha256.Length, "the root Windows chained it to");
        Assert.IsTrue(signed.ProductVersion.Length > 0);
        StringAssert.Matches(signed.FileVersion, new System.Text.RegularExpressions.Regex(@"^\d+\.\d+\.\d+\.\d+$"));

        // Not ours to install: Microsoft is not SecReview's publisher.
        Assert.IsNotNull(UpdateApplier.Refusal(signed, Publisher, "1.4.0", "1.3.0"));

        string unsigned = Path.Combine(_folder, "unsigned.exe");
        File.WriteAllBytes(unsigned, Setup);
        InstallerSignature none = host.Inspect(unsigned);
        Assert.IsFalse(none.Valid);
        Assert.IsNotNull(none.Problem);

        // A signed file with one byte changed is no longer validly signed.
        string changed = Path.Combine(_folder, "changed.exe");
        byte[] bytes = File.ReadAllBytes(dotnet);
        bytes[bytes.Length / 2] ^= 0xFF;
        File.WriteAllBytes(changed, bytes);
        Assert.IsFalse(host.Inspect(changed).Valid);
    }

    // --- Stand-ins.

    private sealed class Clock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class Launcher(Func<string, Task>? helper, bool declined = false) : IElevatedLauncher
    {
        public Task Helper { get; private set; } = Task.CompletedTask;

        public ElevatedProcess? Start(string pipeName)
        {
            if (declined)
            {
                return null;
            }

            Helper = Task.Run(() => helper!(pipeName));
            return new ElevatedProcess(Environment.ProcessId);
        }
    }

    private sealed class Downloader : IUpdateDownloader
    {
        public byte[]? Manifest { get; init; }

        public byte[]? Setup { get; init; }

        public string? Failure { get; init; }

        public string? ManifestFailure { get; init; }

        public List<Uri> Asked { get; } = [];

        public Task<byte[]> GetAsync(Uri url, int maximumBytes, CancellationToken cancellation)
        {
            Asked.Add(url);
            return ManifestFailure is not null ? throw new UpdateTransportException(ManifestFailure) : Task.FromResult(Manifest!);
        }

        public async Task DownloadAsync(Uri url, long maximumBytes, Stream destination, Action<long, long>? progress, CancellationToken cancellation)
        {
            Asked.Add(url);
            if (Failure is not null)
            {
                throw new UpdateTransportException(Failure);
            }

            await destination.WriteAsync(Setup!, cancellation);
            progress?.Invoke(Setup!.Length, Setup.Length);
        }
    }

    private sealed class Host(string folder) : IUpdateHost
    {
        public bool Elevated { get; init; } = true;

        public bool SameUser { get; init; } = true;

        public InstallerSignature Signature { get; init; } = Good();

        public int Inspected { get; private set; }

        public List<(string Path, IReadOnlyList<string> Arguments)> Started { get; } = [];

        public bool IsElevated => Elevated;

        public string CreateWorkFolder() => Directory.CreateDirectory(Path.Combine(folder, "work")).FullName;

        public InstallerSignature Inspect(string path)
        {
            Inspected++;

            // The file is held open for reading only while it is looked at and started.
            Assert.ThrowsExactly<IOException>(() => File.WriteAllText(path, "changed"));
            return Signature;
        }

        public void Start(string path, IReadOnlyList<string> arguments) => Started.Add((path, arguments));

        public bool CallerIsSameUser(NamedPipeClientStream pipe) => SameUser;
    }
}
