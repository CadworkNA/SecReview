using SecReview.Checks;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.Checks;

[TestClass]
public sealed class CheckRunnerTests
{
    private static readonly TimeSpan ShortLimit = TimeSpan.FromMilliseconds(200);

    private static CheckRunner Runner(
        CheckSelection selection = CheckSelection.All,
        bool elevated = false,
        TimeSpan? timeout = null,
        PrivacyFilter? privacy = null) =>
        new(new FakeProbes().Build(), TimeProvider.System, selection, elevated, timeout, privacy ?? PrivacyFilter.None);

    [TestMethod]
    public async Task RunAsync_ReturnsOneResultPerCheck_InTheOrderGiven()
    {
        ICheck[] checks =
        [
            new StubCheck("a", _ => CheckOutcome.Pass("fine")),
            new StubCheck("b", _ => CheckOutcome.Fail("broken", Finding.Problem("thing", "off", "on"))),
            new StubCheck("c", _ => CheckOutcome.NotApplicable("no such hardware")),
        ];

        var results = await Runner().RunAsync(checks);

        CollectionAssert.AreEqual(new[] { "a", "b", "c" }, results.Select(r => r.CheckId).ToArray());
        Assert.AreEqual(CheckStatus.Pass, results[0].Outcome.Status);
        Assert.AreEqual(CheckStatus.Fail, results[1].Outcome.Status);
        Assert.AreEqual("off", results[1].Outcome.Findings[0].Found);
        Assert.AreEqual(CheckStatus.NotApplicable, results[2].Outcome.Status);
        Assert.IsTrue(results.All(r => !r.Elevated));
    }

    [TestMethod]
    public async Task ACheckThatThrows_BecomesCouldNotCheck_AndTheOthersStillRun()
    {
        ICheck[] checks =
        [
            new StubCheck("throws", _ => throw new InvalidOperationException("boom")),
            new StubCheck("fine", _ => CheckOutcome.Pass("fine")),
        ];

        var results = await Runner().RunAsync(checks);

        Assert.AreEqual(CheckStatus.Error, results[0].Outcome.Status);
        StringAssert.Contains(results[0].Outcome.Summary, "InvalidOperationException");
        StringAssert.Contains(results[0].Outcome.Summary, "boom");
        Assert.AreEqual(CheckStatus.Pass, results[1].Outcome.Status);
    }

    [TestMethod]
    public async Task ACheckThatThrows_IsAlsoHandedOver_ForReportingTheBug()
    {
        var handed = new List<(string CheckId, Exception Error)>();
        var runner = new CheckRunner(
            new FakeProbes().Build(), TimeProvider.System, CheckSelection.All, isElevated: false, privacy: PrivacyFilter.None,
            onUnexpected: (id, error) => handed.Add((id, error)));
        ICheck[] checks =
        [
            new StubCheck("throws", _ => throw new InvalidOperationException("boom")),
            new StubCheck("fails", _ => CheckOutcome.Fail("off")),
            new StubCheck("cannot", _ => CheckOutcome.Error("Windows did not answer.")),
        ];

        await runner.RunAsync(checks);

        Assert.AreEqual(1, handed.Count, "a failing check, or one that could not be answered, is not a bug in SecReview");
        Assert.AreEqual("throws", handed[0].CheckId);
        Assert.IsInstanceOfType<InvalidOperationException>(handed[0].Error);
    }

    [TestMethod]
    public async Task ACheckThatHangs_IsReportedAsNotFinished_AndTheOthersStillRun()
    {
        using var never = new ManualResetEventSlim();
        ICheck[] checks =
        [
            new StubCheck("hangs", _ =>
            {
                never.Wait(TimeSpan.FromSeconds(30));
                return CheckOutcome.Pass("too late");
            }),
            new StubCheck("fine", _ => CheckOutcome.Pass("fine")),
        ];

        var results = await Runner(timeout: ShortLimit).RunAsync(checks);
        never.Set();

        Assert.AreEqual(CheckStatus.Error, results[0].Outcome.Status);
        StringAssert.Contains(results[0].Outcome.Summary, "did not finish");
        Assert.AreEqual(CheckStatus.Pass, results[1].Outcome.Status);
    }

    [TestMethod]
    public async Task ACheckThatHangs_IsToldToStop()
    {
        using var stopped = new ManualResetEventSlim();
        var check = new StubCheck("hangs", context =>
        {
            context.Cancellation.WaitHandle.WaitOne(TimeSpan.FromSeconds(30));
            stopped.Set();
            return CheckOutcome.Pass("too late");
        });

        await Runner(timeout: ShortLimit).RunAsync([check]);

        Assert.IsTrue(stopped.Wait(TimeSpan.FromSeconds(10)), "the check's cancellation token was not signalled");
    }

    [TestMethod]
    public async Task ACheckThatReturnsNothing_BecomesCouldNotCheck_NeverAPass()
    {
        ICheck[] checks =
        [
            new StubCheck("null", _ => null!),
            new StubCheck("blank", _ => new CheckOutcome(CheckStatus.Pass, "  ", [])),
        ];

        var results = await Runner().RunAsync(checks);

        Assert.IsTrue(results.All(r => r.Outcome.Status == CheckStatus.Error));
    }

    [TestMethod]
    public async Task NotElevated_AdministratorOnlyCheck_IsNotRun_AndSaysNeedsAdministrator()
    {
        bool ran = false;
        var check = new StubCheck("admin", _ => { ran = true; return CheckOutcome.Pass("fine"); }, AdminNeed.Yes);

        var results = await Runner(elevated: false).RunAsync([check]);

        Assert.IsFalse(ran);
        Assert.AreEqual(CheckStatus.NeedsAdmin, results[0].Outcome.Status);
    }

    [TestMethod]
    public async Task Elevated_MachineChecksRun_IncludingAdministratorOnlyOnes()
    {
        ICheck[] checks =
        [
            new StubCheck("plain", _ => CheckOutcome.Pass("fine")),
            new StubCheck("admin", _ => CheckOutcome.Pass("fine"), AdminNeed.Yes),
        ];

        var results = await Runner(CheckSelection.All, elevated: true).RunAsync(checks);

        Assert.AreEqual(2, results.Count);
        Assert.IsTrue(results.All(r => r.Elevated && r.Outcome.Status == CheckStatus.Pass));
    }

    [TestMethod]
    public async Task Elevated_AUserScopeCheck_IsNeverRun_AndSaysWhy()
    {
        // An elevated process may be another account's: it must not report that account's
        // settings as the signed-in user's.
        bool ran = false;
        var check = new StubCheck("user", _ => { ran = true; return CheckOutcome.Pass("fine"); }, scope: CheckScope.User);

        var results = await Runner(CheckSelection.All, elevated: true).RunAsync([check]);

        Assert.IsFalse(ran);
        Assert.AreEqual(CheckStatus.Error, results[0].Outcome.Status);
        StringAssert.Contains(results[0].Outcome.Summary, "without administrator rights");
    }

    [TestMethod]
    public async Task NotElevated_AUserScopeCheck_Runs()
    {
        var check = new StubCheck("user", _ => CheckOutcome.Pass("fine"), scope: CheckScope.User);

        var results = await Runner(CheckSelection.All, elevated: false).RunAsync([check]);

        Assert.AreEqual(CheckStatus.Pass, results[0].Outcome.Status);
    }

    [TestMethod]
    public async Task AdministratorOnlySelection_RunsOnlyMachineChecksThatNeedAdministrator()
    {
        ICheck[] checks =
        [
            new StubCheck("plain", _ => CheckOutcome.Pass("fine")),
            new StubCheck("admin", _ => CheckOutcome.Pass("fine"), AdminNeed.Yes),
            new StubCheck("detail", _ => CheckOutcome.Pass("fine"), AdminNeed.ForFullDetail),
            new StubCheck("user", _ => CheckOutcome.Pass("fine"), AdminNeed.Yes, CheckScope.User),
        ];

        var results = await Runner(CheckSelection.AdministratorOnly, elevated: true).RunAsync(checks);

        CollectionAssert.AreEqual(new[] { "admin", "detail" }, results.Select(r => r.CheckId).ToArray());
        Assert.IsTrue(results.All(r => r.Elevated && r.Outcome.Status == CheckStatus.Pass));
    }

    [TestMethod]
    public async Task RunOne_OfACheckOutsideTheSelection_IsRefused()
    {
        // "Check again" must not be a way to run a user-scope check in the elevated helper.
        bool ran = false;
        var userCheck = new StubCheck("user", _ => { ran = true; return CheckOutcome.Pass("fine"); }, scope: CheckScope.User);
        CheckRunner runner = Runner(CheckSelection.AdministratorOnly, elevated: true);

        await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => runner.RunOneAsync(userCheck));
        Assert.IsFalse(ran);
    }

    [TestMethod]
    public async Task Checks_SeeWhetherTheRunIsElevated()
    {
        bool? seen = null;
        var check = new StubCheck("x", context => { seen = context.IsElevated; return CheckOutcome.Pass("fine"); });

        await Runner(elevated: true).RunAsync([check]);

        Assert.AreEqual(true, seen);
    }

    [TestMethod]
    public async Task Results_HaveUserAndComputerNamesRemoved()
    {
        var privacy = new PrivacyFilter(@"C:\Users\alice", "alice", "DESKTOP-EXAMPLE");
        ICheck[] checks =
        [
            new StubCheck("throws", _ => throw new UnauthorizedAccessException(@"Access to the path 'C:\Users\alice\.npmrc' is denied.")),
            new StubCheck("finding", _ => CheckOutcome.Fail(
                "Found on DESKTOP-EXAMPLE", Finding.Problem(@"C:\Users\alice\.gitconfig", "token of alice", "none", @"C:\Users\alice\.gitconfig:3"))),
        ];

        var results = await Runner(privacy: privacy).RunAsync(checks);

        string everything = string.Join("|", results.SelectMany(r =>
            r.Outcome.Findings.SelectMany(f => new[] { f.Item, f.Found, f.Expected, f.Source ?? string.Empty })
                .Append(r.Outcome.Summary)));
        Assert.IsFalse(everything.Contains("alice", StringComparison.OrdinalIgnoreCase), everything);
        Assert.IsFalse(everything.Contains("DESKTOP-EXAMPLE", StringComparison.OrdinalIgnoreCase), everything);
        StringAssert.Contains(everything, @"%USERPROFILE%\.npmrc");
    }

    [TestMethod]
    public async Task ManyChecks_AllGetAResult()
    {
        ICheck[] checks = [.. Enumerable.Range(0, 50).Select(i => new StubCheck($"c{i}", _ => CheckOutcome.Pass("fine")))];

        var results = await Runner().RunAsync(checks);

        Assert.AreEqual(50, results.Count);
        Assert.IsTrue(results.All(r => r is not null && r.Outcome.Status == CheckStatus.Pass));
    }

    [TestMethod]
    public void ATimeLimitThatIsNotPositive_IsRefused()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Runner(timeout: TimeSpan.Zero));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => Runner(timeout: TimeSpan.FromSeconds(-1)));
    }

    [TestMethod]
    public void AStatusNobodySet_IsCouldNotCheck_NeverAPass()
    {
        // What an unfilled field or array slot holds.
        var slots = new CheckStatus[1];

        Assert.AreEqual(CheckStatus.Error, slots[0]);
    }

    private sealed class StubCheck(
        string id,
        Func<CheckContext, CheckOutcome> run,
        AdminNeed needsAdmin = AdminNeed.No,
        CheckScope scope = CheckScope.Machine) : ICheck
    {
        public CheckDefinition Definition { get; } =
            new(id, CheckCategory.SystemIntegrity, Severity.Medium, needsAdmin, scope);

        public CheckOutcome Run(CheckContext context) => run(context);
    }
}
