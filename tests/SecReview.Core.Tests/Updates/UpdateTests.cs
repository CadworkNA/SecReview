using System.Net;
using System.Text;
using SecReview.Checks;
using SecReview.Probing;
using SecReview.Tests.Checks;
using SecReview.Tests.Fakes;
using SecReview.Updates;

namespace SecReview.Tests.Updates;

[TestClass]
public sealed class UpdateTests
{
    private const string Hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string ManifestAddress = "https://github.com/made-up/secreview/releases/latest/download/latest.json";
    private const string SetupAddress = "https://github.com/made-up/secreview/releases/download/v1.4.0/SecReview-1.4.0-setup.exe";

    private static readonly DateTimeOffset Now = CheckTesting.Now;
    private static readonly UpdateSource Source = new(ManifestAddress);

    private static byte[] Manifest(
        string version = "1.4.0", string url = SetupAddress, string sha256 = Hash, string published = "2026-11-01T10:00:00Z", string? notes = "Two new checks.") =>
        Encoding.UTF8.GetBytes(
            $$"""{"version":"{{version}}","url":"{{url}}","sha256":"{{sha256}}","published":"{{published}}","notes":{{(notes is null ? "null" : $"\"{notes}\"")}}}""");

    // --- Where SecReview fetches from.

    [TestMethod]
    public void ABuildWithoutAnAddress_NeverLooks()
    {
        Assert.IsFalse(new UpdateSource(null).IsConfigured);
        Assert.IsFalse(new UpdateSource("  ").IsConfigured);
        Assert.IsFalse(new UpdateSource("http://github.com/made-up/latest.json").IsConfigured, "not without encryption");
        Assert.IsFalse(new UpdateSource("https://user:secret@github.com/latest.json").IsConfigured, "no sign-in in an address");
        Assert.IsFalse(new UpdateSource("https://github.com:8443/latest.json").IsConfigured, "no unusual port");
        Assert.IsFalse(new UpdateSource("not an address").IsConfigured);
        Assert.IsTrue(Source.IsConfigured);
    }

    [TestMethod]
    public void OnlyTheManifestsHost_AndForGitHubItsDownloadHosts_AreFetchedFrom()
    {
        Assert.IsTrue(Source.Allows(new Uri(SetupAddress)));
        Assert.IsTrue(Source.Allows(new Uri("https://release-assets.githubusercontent.com/made/up?sig=1")));
        Assert.IsTrue(Source.Allows(new Uri("https://objects.githubusercontent.com/made/up")));
        Assert.IsTrue(Source.Allows(new Uri("https://GITHUB.com/made/up")), "host names are not case-sensitive");

        Assert.IsFalse(Source.Allows(new Uri("https://github.com.made-up.example/x")));
        Assert.IsFalse(Source.Allows(new Uri("https://made-up.example/x")));
        Assert.IsFalse(Source.Allows(new Uri("http://github.com/x")));
        Assert.IsFalse(Source.Allows(new Uri("https://github.com@made-up.example/x")));
        Assert.IsFalse(Source.Allows(new Uri("https://github.com:444/x")));
        Assert.IsFalse(Source.Allows(new Uri("file:///C:/made/up/setup.exe")));

        var own = new UpdateSource("https://downloads.made-up.example/secreview/latest.json");
        Assert.IsTrue(own.Allows(new Uri("https://downloads.made-up.example/secreview/setup.exe")));
        Assert.IsFalse(own.Allows(new Uri("https://github.com/made/up")), "GitHub's hosts only for a manifest on GitHub");
        Assert.IsFalse(new UpdateSource(null).Allows(new Uri(SetupAddress)));
    }

    // --- The manifest.

    [TestMethod]
    public void AManifest_IsReadWhole()
    {
        UpdateManifest manifest = UpdateManifest.Parse(Manifest(), Source, Now, out string? problem)!;

        Assert.IsNull(problem);
        Assert.AreEqual("1.4.0", manifest.Version);
        Assert.AreEqual(new Uri(SetupAddress), manifest.Url);
        Assert.AreEqual(Hash, manifest.Sha256);
        Assert.AreEqual(new DateTimeOffset(2026, 11, 1, 10, 0, 0, TimeSpan.Zero), manifest.Published);
        Assert.AreEqual("Two new checks.", manifest.Notes);

        UpdateManifest again = UpdateManifest.Parse(manifest.ToBytes(), Source, Now, out _)!;
        Assert.AreEqual(manifest, again, "what the release workflow writes is what the app reads");
        Assert.AreEqual(string.Empty, UpdateManifest.Parse(Manifest(notes: null), Source, Now, out _)!.Notes);
    }

    [TestMethod]
    [DataRow("version", """{"url":"U","sha256":"H","published":"2026-11-01T10:00:00Z"}""")]
    [DataRow("version", """{"version":"v1.4.0","url":"U","sha256":"H","published":"2026-11-01T10:00:00Z"}""")]
    [DataRow("version", """{"version":"1.4","url":"U","sha256":"H","published":"2026-11-01T10:00:00Z"}""")]
    [DataRow("version", """{"version":"latest","url":"U","sha256":"H","published":"2026-11-01T10:00:00Z"}""")]
    [DataRow("download", """{"version":"1.4.0","url":"https://made-up.example/setup.exe","sha256":"H","published":"2026-11-01T10:00:00Z"}""")]
    [DataRow("download", """{"version":"1.4.0","url":"http://github.com/made-up/setup.exe","sha256":"H","published":"2026-11-01T10:00:00Z"}""")]
    [DataRow("download", """{"version":"1.4.0","url":"setup.exe","sha256":"H","published":"2026-11-01T10:00:00Z"}""")]
    [DataRow("checksum", """{"version":"1.4.0","url":"U","sha256":"0123","published":"2026-11-01T10:00:00Z"}""")]
    [DataRow("checksum", """{"version":"1.4.0","url":"U","sha256":"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF","published":"2026-11-01T10:00:00Z"}""")]
    [DataRow("incomplete", """{"version":"1.4.0","url":"U","published":"2026-11-01T10:00:00Z"}""")]
    [DataRow("date", """{"version":"1.4.0","url":"U","sha256":"H","published":"soon"}""")]
    [DataRow("date", """{"version":"1.4.0","url":"U","sha256":"H","published":"2031-01-01T00:00:00Z"}""")]
    [DataRow("date", """{"version":"1.4.0","url":"U","sha256":"H","published":"1999-01-01T00:00:00Z"}""")]
    [DataRow("not the list", """<html>Sign in</html>""")]
    [DataRow("not the list", """[1, 2, 3]""")]
    [DataRow("not the list", """{"version":"1.4.0", /* a comment */ "url":"U","sha256":"H","published":"2026-11-01T10:00:00Z"}""")]
    [DataRow("incomplete", """null""")]
    public void AManifestThatIsNotWhollyRight_IsNotUsed(string reason, string json)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json.Replace("\"U\"", $"\"{SetupAddress}\"", StringComparison.Ordinal).Replace("\"H\"", $"\"{Hash}\"", StringComparison.Ordinal));

        Assert.IsNull(UpdateManifest.Parse(bytes, Source, Now, out string? problem));
        StringAssert.Contains(problem, reason);
    }

    [TestMethod]
    public void AManifestTooLargeToBeOne_IsNotRead_AndNotesAreKeptShortAndPlain()
    {
        Assert.IsNull(UpdateManifest.Parse(new byte[UpdateManifest.MaximumBytes + 1], Source, Now, out string? problem));
        StringAssert.Contains(problem, "too large");

        string notes = new string('n', 5000) + "\\u0007\\u001b[31m";
        UpdateManifest manifest = UpdateManifest.Parse(Manifest(notes: notes), Source, Now, out _)!;
        Assert.AreEqual(UpdateManifest.MaximumNotesLength, manifest.Notes.Length);
        Assert.IsFalse(UpdateManifest.Parse(Manifest(notes: "a\\u0007b\\nc"), Source, Now, out _)!.Notes.Contains('\u0007'));
        Assert.AreEqual("a\nc", UpdateManifest.Parse(Manifest(notes: "a\\nc"), Source, Now, out _)!.Notes);
    }

    // --- Versions and timing.

    [TestMethod]
    [DataRow("1.4.0", "1.3.9", true)]
    [DataRow("1.10.0", "1.9.0", true)]
    [DataRow("2.0.0", "1.99.99", true)]
    [DataRow("1.4.0", "1.4.0", false)]
    [DataRow("1.3.0", "1.4.0", false)]
    [DataRow("1.4.0", "0.0.0-dev", true)]
    [DataRow("1.5.0-rc.1", "1.4.0", false)]
    [DataRow("1.5.0-rc.2", "1.5.0-rc.1", true)]
    [DataRow("1.5.0", "1.5.0-rc.1", true)]
    [DataRow("1.4.0", "not a version", false)]
    [DataRow("newest", "1.4.0", false)]
    public void OnlyAHigherVersion_IsAnUpdate_AndAPreReleaseOnlyForThoseWhoRunOne(string offered, string installed, bool newer)
    {
        Assert.AreEqual(newer, UpdateRules.IsNewer(offered, installed));
    }

    [TestMethod]
    public void SecReviewLooksOnceADay_SoonerAfterAFailure_AndAtOnceWhenTheClockWasChanged()
    {
        Assert.IsTrue(UpdateRules.IsCheckDue(new UpdateState(), Now), "never looked");

        var fine = new UpdateState { CheckedAt = Now.AddHours(-23), Outcome = UpdateOutcome.UpToDate };
        Assert.IsFalse(UpdateRules.IsCheckDue(fine, Now));
        Assert.IsTrue(UpdateRules.IsCheckDue(fine with { CheckedAt = Now.AddHours(-24) }, Now));
        Assert.IsFalse(UpdateRules.IsCheckDue(fine with { CheckedAt = Now.AddHours(-24.4) }, Now, spread: 0.5), "each PC at its own time");
        Assert.IsTrue(UpdateRules.IsCheckDue(fine with { CheckedAt = Now.AddHours(-24.6) }, Now, spread: 0.5));

        var failed = new UpdateState { CheckedAt = Now.AddHours(-1), Outcome = UpdateOutcome.Failed };
        Assert.IsFalse(UpdateRules.IsCheckDue(failed, Now));
        Assert.IsTrue(UpdateRules.IsCheckDue(failed with { CheckedAt = Now.AddHours(-2) }, Now));

        Assert.IsTrue(UpdateRules.IsCheckDue(fine with { CheckedAt = Now.AddDays(3) }, Now), "dated after now");
    }

    // --- Looking.

    private static UpdateChecker Checker(Transport transport, string installed = "1.3.0", UpdateSource? source = null) =>
        new(source ?? Source, transport, new Clock(Now), installed);

    [TestMethod]
    public async Task ANewerVersion_IsFound_WithItsDateAndNotes()
    {
        var transport = new Transport { Answer = Manifest() };

        UpdateState state = await Checker(transport).CheckAsync();

        Assert.AreEqual(UpdateOutcome.Available, state.Outcome);
        Assert.AreEqual("1.4.0", state.Available);
        Assert.AreEqual("Two new checks.", state.Notes);
        Assert.AreEqual(Now, state.CheckedAt);
        Assert.AreEqual("1.3.0", state.CheckedBy);
        Assert.AreEqual(new Uri(ManifestAddress), transport.Asked.Single());
    }

    [TestMethod]
    public async Task TheSameOrAnOlderVersion_MeansUpToDate()
    {
        Assert.AreEqual(UpdateOutcome.UpToDate, (await Checker(new Transport { Answer = Manifest() }, installed: "1.4.0").CheckAsync()).Outcome);
        Assert.AreEqual(UpdateOutcome.UpToDate, (await Checker(new Transport { Answer = Manifest() }, installed: "2.0.0").CheckAsync()).Outcome);
    }

    [TestMethod]
    public async Task ALookThatFails_SaysWhy_AndIsNeverUpToDate()
    {
        UpdateState offline = await Checker(new Transport { Failure = "the server could not be reached" }).CheckAsync();
        Assert.AreEqual(UpdateOutcome.Failed, offline.Outcome);
        Assert.AreEqual("Could not look for updates: the server could not be reached.", offline.Problem);

        UpdateState garbage = await Checker(new Transport { Answer = "<html>"u8.ToArray() }).CheckAsync();
        Assert.AreEqual(UpdateOutcome.Failed, garbage.Outcome);
        StringAssert.Contains(garbage.Problem, "not the list of versions");

        UpdateState slow = await Checker(new Transport { TimesOut = true }).CheckAsync();
        Assert.AreEqual(UpdateOutcome.Failed, slow.Outcome);
        StringAssert.Contains(slow.Problem, "too long");

        var none = new Transport { Answer = Manifest() };
        UpdateState notConfigured = await Checker(none, source: new UpdateSource(null)).CheckAsync();
        Assert.AreEqual(UpdateOutcome.Failed, notConfigured.Outcome);
        Assert.AreEqual(0, none.Asked.Count, "a build without an address asks nobody");
    }

    // --- Fetching.

    [TestMethod]
    public async Task AFetch_SaysOnlyTheProductAndVersion_AndFollowsGitHubToItsFiles()
    {
        var handler = new Handler(request => request.RequestUri!.Host switch
        {
            "github.com" => Redirect("https://release-assets.githubusercontent.com/made/up?sig=1"),
            _ => Ok("the file"u8.ToArray()),
        });
        using var transport = new HttpUpdateTransport(Source, handler);

        byte[] bytes = await transport.GetAsync(new Uri(ManifestAddress), 1000, CancellationToken.None);

        CollectionAssert.AreEqual("the file"u8.ToArray(), bytes);
        Assert.AreEqual(2, handler.Requests.Count);
        foreach (HttpRequestMessage request in handler.Requests)
        {
            Assert.AreEqual(HttpMethod.Get, request.Method);
            StringAssert.StartsWith(request.Headers.UserAgent.ToString(), "SecReview/");
            Assert.IsFalse(request.Headers.Contains("Cookie") || request.Headers.Contains("Authorization"));
            Assert.AreEqual(1, request.Headers.Count(), "the product's name and version, nothing else");
        }
    }

    [TestMethod]
    public async Task AServerThatSendsSecReviewElsewhere_IsNotFollowed()
    {
        var handler = new Handler(_ => Redirect("https://made-up.example/setup.exe"));
        using var transport = new HttpUpdateTransport(Source, handler);

        UpdateTransportException refused = await Assert.ThrowsExactlyAsync<UpdateTransportException>(
            () => transport.GetAsync(new Uri(ManifestAddress), 1000, CancellationToken.None));

        StringAssert.Contains(refused.Message, "does not fetch from");
        Assert.AreEqual(1, handler.Requests.Count, "the other address was never asked");

        var downgrade = new Handler(_ => Redirect("http://github.com/made-up/latest.json"));
        using var second = new HttpUpdateTransport(Source, downgrade);
        await Assert.ThrowsExactlyAsync<UpdateTransportException>(() => second.GetAsync(new Uri(ManifestAddress), 1000, CancellationToken.None));
        Assert.AreEqual(1, downgrade.Requests.Count);
    }

    [TestMethod]
    public async Task EndlessForwarding_AFileTooLarge_AndAnErrorAnswer_AllFail()
    {
        var loop = new Handler(_ => Redirect(ManifestAddress));
        using var first = new HttpUpdateTransport(Source, loop);
        UpdateTransportException tooMany = await Assert.ThrowsExactlyAsync<UpdateTransportException>(
            () => first.GetAsync(new Uri(ManifestAddress), 1000, CancellationToken.None));
        StringAssert.Contains(tooMany.Message, "too many times");
        Assert.AreEqual(6, loop.Requests.Count);

        using var second = new HttpUpdateTransport(Source, new Handler(_ => Ok(new byte[2000])));
        UpdateTransportException tooLarge = await Assert.ThrowsExactlyAsync<UpdateTransportException>(
            () => second.GetAsync(new Uri(ManifestAddress), 1000, CancellationToken.None));
        StringAssert.Contains(tooLarge.Message, "larger");

        // A server that does not say how long the file is: the limit holds while reading.
        using var third = new HttpUpdateTransport(Source, new Handler(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(new Endless()) }));
        await Assert.ThrowsExactlyAsync<UpdateTransportException>(() => third.GetAsync(new Uri(ManifestAddress), 1000, CancellationToken.None));

        using var fourth = new HttpUpdateTransport(Source, new Handler(_ => new HttpResponseMessage(HttpStatusCode.NotFound)));
        UpdateTransportException notFound = await Assert.ThrowsExactlyAsync<UpdateTransportException>(
            () => fourth.GetAsync(new Uri(ManifestAddress), 1000, CancellationToken.None));
        StringAssert.Contains(notFound.Message, "404");

        using var fifth = new HttpUpdateTransport(Source, new Handler(_ => Ok([])));
        await Assert.ThrowsExactlyAsync<UpdateTransportException>(() => fifth.GetAsync(new Uri("https://made-up.example/latest.json"), 1000, CancellationToken.None));
    }

    [TestMethod]
    public async Task ADownload_GoesToTheStream_AndReportsItsProgress()
    {
        byte[] file = new byte[300_000];
        new Random(7).NextBytes(file);
        using var transport = new HttpUpdateTransport(Source, new Handler(_ => Ok(file)));
        using var destination = new MemoryStream();
        var seen = new List<(long Done, long Total)>();

        await transport.DownloadAsync(new Uri(SetupAddress), 1_000_000, destination, (done, total) => seen.Add((done, total)), CancellationToken.None);

        CollectionAssert.AreEqual(file, destination.ToArray());
        Assert.AreEqual((300_000L, 300_000L), seen[^1]);
        Assert.IsTrue(seen.Count > 1);
    }

    // --- What is kept.

    [TestMethod]
    public void WhatWasFound_IsKept_AndBelievedOnlyByTheVersionThatFoundIt()
    {
        string folder = Path.Combine(Path.GetTempPath(), "SecReview.Tests." + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new UpdateStateStore(folder);
            Assert.AreEqual(UpdateOutcome.Unknown, store.Load().Outcome);

            var found = new UpdateState
            {
                CheckedAt = Now, CheckedBy = "1.3.0", Outcome = UpdateOutcome.Available, Available = "1.4.0", Published = Now.AddDays(-3), Notes = "Two new checks.",
            };
            Assert.IsTrue(store.Save(found));
            UpdateState read = store.Load();
            Assert.AreEqual(found, read);

            Assert.AreEqual(UpdateOutcome.Available, read.For("1.3.0", Now).Outcome);
            Assert.AreEqual(UpdateOutcome.Unknown, read.For("1.4.0", Now).Outcome, "after the update, what the old version found is void");
            Assert.AreEqual(UpdateOutcome.Unknown, read.For("1.3.0", Now.AddDays(-2)).Outcome, "dated after now");
            Assert.AreEqual(UpdateOutcome.Unknown, (read with { Available = "1.2.0" }).For("1.3.0", Now).Outcome, "not newer after all");

            File.WriteAllText(Path.Combine(folder, UpdateState.FileName), "{ not json");
            Assert.AreEqual(UpdateOutcome.Unknown, store.Load().Outcome);
            File.WriteAllText(Path.Combine(folder, UpdateState.FileName), """{"version":2,"outcome":"UpToDate"}""");
            Assert.AreEqual(UpdateOutcome.Unknown, store.Load().Outcome, "another version's file");
        }
        finally
        {
            if (Directory.Exists(folder))
            {
                Directory.Delete(folder, recursive: true);
            }
        }
    }

    // --- The check.

    private const string DataFolder = @"C:\Users\made-up\AppData\Local\SecReview";

    private static CheckOutcome RunCheck(UpdateState? state, FakeProbes? probes = null, UpdateSource? source = null, bool elevated = false)
    {
        probes ??= new FakeProbes();
        if (state is not null)
        {
            probes.WithFile($@"{DataFolder}\{UpdateState.FileName}", Encoding.UTF8.GetString(System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(state, UpdateJson.Default.UpdateState)));
        }

        return new SecReviewUpdateCheck(source ?? Source, () => DataFolder, "1.3.0").Run(probes, elevated);
    }

    [TestMethod]
    public void TheCheck_PassesOnlyWhenSecReviewRecentlyFoundItselfUpToDate()
    {
        CheckOutcome pass = RunCheck(new UpdateState { CheckedAt = Now.AddHours(-5), CheckedBy = "1.3.0", Outcome = UpdateOutcome.UpToDate });
        Assert.AreEqual(CheckStatus.Pass, pass.Status);
        Assert.AreEqual("SecReview is up to date.", pass.Summary);

        CheckOutcome old = RunCheck(new UpdateState { CheckedAt = Now.AddDays(-8), CheckedBy = "1.3.0", Outcome = UpdateOutcome.UpToDate });
        Assert.AreEqual(CheckStatus.Error, old.Status, "last week's answer is not today's");
        StringAssert.Contains(old.Summary, "last looked for updates 8 days ago");

        CheckOutcome never = RunCheck(null);
        Assert.AreEqual(CheckStatus.Error, never.Status);
        Assert.AreEqual("SecReview has not looked for updates yet.", never.Summary);

        CheckOutcome otherVersion = RunCheck(new UpdateState { CheckedAt = Now.AddHours(-5), CheckedBy = "1.2.0", Outcome = UpdateOutcome.UpToDate });
        Assert.AreEqual(CheckStatus.Error, otherVersion.Status, "what an older version found says nothing about this one");
    }

    [TestMethod]
    public void TheCheck_FailsWhenThereIsANewerVersion_AndSaysSoWhenItCouldNotLook()
    {
        CheckOutcome fail = RunCheck(new UpdateState
        {
            CheckedAt = Now.AddHours(-5), CheckedBy = "1.3.0", Outcome = UpdateOutcome.Available, Available = "1.4.0", Published = Now.AddDays(-3),
        });
        Assert.AreEqual(CheckStatus.Fail, fail.Status);
        Assert.AreEqual("Version 1.4.0 of SecReview is available, released 3 days ago.", fail.Summary);
        CollectionAssert.AreEqual(new[] { "SecReview: Version 1.3.0 (expected Version 1.4.0) [problem]" }, fail.Rows());

        CheckOutcome error = RunCheck(new UpdateState
        {
            CheckedAt = Now.AddHours(-1), CheckedBy = "1.3.0", Outcome = UpdateOutcome.Failed, Problem = "Could not look for updates: the server could not be reached.",
        });
        Assert.AreEqual(CheckStatus.Error, error.Status);
        Assert.AreEqual("Could not look for updates: the server could not be reached.", error.Summary);
    }

    [TestMethod]
    public void TheCheck_DoesNotApply_WithoutAnAddressOrWhenTheOrganisationSaidNo()
    {
        var upToDate = new UpdateState { CheckedAt = Now.AddHours(-5), CheckedBy = "1.3.0", Outcome = UpdateOutcome.UpToDate };

        Assert.AreEqual(CheckStatus.NotApplicable, RunCheck(upToDate, source: new UpdateSource(null)).Status);

        FakeProbes policy = new FakeProbes().WithRegistryNumber(RegistryRoot.LocalMachine, UpdatePolicy.Key, UpdatePolicy.NoUpdateCheckValue, 1);
        CheckOutcome off = RunCheck(upToDate, policy);
        Assert.AreEqual(CheckStatus.NotApplicable, off.Status);
        Assert.IsTrue(off.ManagedByPolicy);

        FakeProbes zero = new FakeProbes().WithRegistryNumber(RegistryRoot.LocalMachine, UpdatePolicy.Key, UpdatePolicy.NoUpdateCheckValue, 0);
        Assert.AreEqual(CheckStatus.Pass, RunCheck(upToDate, zero).Status, "0 means the policy is not set");
    }

    [TestMethod]
    public void APolicy_ThatCannotBeRead_CountsAsSet()
    {
        var registry = new FakeProbes { RegistryFailure = ProbeFailure.AccessDenied("made up") };
        UpdatePolicy policy = UpdatePolicy.Read(registry.Build().Registry);
        Assert.IsTrue(policy.NoUpdateCheck && policy.NoSelfUpdate);

        UpdatePolicy none = UpdatePolicy.Read(new FakeProbes().Build().Registry);
        Assert.IsFalse(none.NoUpdateCheck || none.NoSelfUpdate);

        UpdatePolicy notify = UpdatePolicy.Read(
            new FakeProbes().WithRegistryNumber(RegistryRoot.LocalMachine, UpdatePolicy.Key, UpdatePolicy.NoSelfUpdateValue, 1).Build().Registry);
        Assert.IsTrue(notify.NoSelfUpdate && !notify.NoUpdateCheck);
    }

    // --- Stand-ins.

    private static HttpResponseMessage Ok(byte[] body) => new(HttpStatusCode.OK) { Content = new ByteArrayContent(body) };

    private static HttpResponseMessage Redirect(string to)
    {
        var response = new HttpResponseMessage(HttpStatusCode.Found);
        response.Headers.Location = new Uri(to);
        return response;
    }

    private sealed class Clock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class Transport : IUpdateTransport
    {
        public byte[]? Answer { get; init; }

        public string? Failure { get; init; }

        public bool TimesOut { get; init; }

        public List<Uri> Asked { get; } = [];

        public Task<byte[]> GetAsync(Uri url, int maximumBytes, CancellationToken cancellation)
        {
            Asked.Add(url);
            if (TimesOut)
            {
                throw new TaskCanceledException();
            }

            return Failure is not null ? throw new UpdateTransportException(Failure) : Task.FromResult(Answer!);
        }
    }

    private sealed class Handler(Func<HttpRequestMessage, HttpResponseMessage> answer) : HttpMessageHandler
    {
        public List<HttpRequestMessage> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            return Task.FromResult(answer(request));
        }
    }

    /// <summary>A stream that never ends.</summary>
    private sealed class Endless : Stream
    {
        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            Array.Clear(buffer, offset, count);
            return count;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
