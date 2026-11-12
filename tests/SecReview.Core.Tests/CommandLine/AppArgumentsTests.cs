using SecReview.CommandLine;

namespace SecReview.Tests.CommandLine;

[TestClass]
public sealed class AppArgumentsTests
{
    [TestMethod]
    public void NoArguments_ShowsTheWindow()
    {
        var role = Assert.IsInstanceOfType<UiRole>(AppArguments.Parse([]));

        Assert.AreEqual(new UiRole(SmokeTest: false, Demo: false, ScreenshotPath: null), role);
    }

    [TestMethod]
    public void SmokeTestSwitch_ShowsTheWindowInSmokeTestMode()
    {
        var role = Assert.IsInstanceOfType<UiRole>(AppArguments.Parse(["--smoke-test"]));
        Assert.IsTrue(role.SmokeTest);
    }

    [TestMethod]
    public void DemoAndScreenshot_CanBeCombined_InAnyOrder()
    {
        var first = Assert.IsInstanceOfType<UiRole>(AppArguments.Parse(["--demo", "--screenshot", @"C:\Temp\a.png"]));
        var second = Assert.IsInstanceOfType<UiRole>(AppArguments.Parse(["--screenshot", @"C:\Temp\a.png", "--demo"]));

        Assert.AreEqual(new UiRole(SmokeTest: false, Demo: true, ScreenshotPath: @"C:\Temp\a.png"), first);
        Assert.AreEqual(first, second);
    }

    [TestMethod]
    [DataRow("mixed", SecReview.Scanning.DemoState.Mixed)]
    [DataRow("all-pass", SecReview.Scanning.DemoState.AllPass)]
    [DataRow("first-run", SecReview.Scanning.DemoState.FirstRun)]
    [DataRow("failed", SecReview.Scanning.DemoState.Failed)]
    [DataRow("loading", SecReview.Scanning.DemoState.Loading)]
    [DataRow("ignored", SecReview.Scanning.DemoState.Ignored)]
    [DataRow("dialogs", SecReview.Scanning.DemoState.Dialogs)]
    public void Demo_CanNameTheStateToShow(string name, SecReview.Scanning.DemoState state)
    {
        var role = Assert.IsInstanceOfType<UiRole>(AppArguments.Parse(["--demo", name, "--screenshot", "a.png"]));

        Assert.IsTrue(role.Demo);
        Assert.AreEqual(state, role.DemoState);
        Assert.AreEqual("a.png", role.ScreenshotPath);
    }

    [TestMethod]
    public void Demo_WithAStateNobodyKnows_IsInvalid_AndAStateWithoutDemoToo()
    {
        Assert.IsInstanceOfType<InvalidRole>(AppArguments.Parse(["--demo", "sideways"]));
        Assert.IsInstanceOfType<InvalidRole>(AppArguments.Parse(["--demo", "All-Pass"]));
        Assert.IsInstanceOfType<InvalidRole>(AppArguments.Parse(["all-pass"]));
        Assert.AreEqual(SecReview.Scanning.DemoState.Mixed, Assert.IsInstanceOfType<UiRole>(AppArguments.Parse(["--demo"])).DemoState);
    }

    [TestMethod]
    public void TheErrorReportTest_TakesAFile_AndNothingElse()
    {
        var role = Assert.IsInstanceOfType<ErrorReportTestRole>(AppArguments.Parse(["--error-report-test", "out.txt"]));
        Assert.AreEqual("out.txt", role.OutputPath);

        Assert.IsInstanceOfType<InvalidRole>(AppArguments.Parse(["--error-report-test"]));
        Assert.IsInstanceOfType<InvalidRole>(AppArguments.Parse(["--error-report-test", "--demo"]));
        Assert.IsInstanceOfType<InvalidRole>(AppArguments.Parse(["--error-report-test", "out.txt", "--demo"]));
        Assert.IsInstanceOfType<InvalidRole>(AppArguments.Parse(["--demo", "--error-report-test", "out.txt"]));
    }

    [TestMethod]
    public void Screenshot_WithoutAFile_IsInvalid()
    {
        Assert.IsInstanceOfType<InvalidRole>(AppArguments.Parse(["--screenshot"]));
        Assert.IsInstanceOfType<InvalidRole>(AppArguments.Parse(["--screenshot", "--demo"]));
        Assert.IsInstanceOfType<InvalidRole>(AppArguments.Parse(["--screenshot", "  "]));
    }

    [TestMethod]
    [DataRow("--Smoke-Test")]
    [DataRow("--tray-typo")]
    [DataRow("C:\\some\\file")]
    [DataRow("")]
    public void UnknownArgument_IsInvalid(string argument)
    {
        Assert.IsInstanceOfType<InvalidRole>(AppArguments.Parse([argument]));
    }

    [TestMethod]
    [DataRow("--smoke-test")]
    [DataRow("--demo")]
    public void RepeatedSwitch_IsInvalid(string argument)
    {
        Assert.IsInstanceOfType<InvalidRole>(AppArguments.Parse([argument, argument]));
    }

    [TestMethod]
    public void RepeatedScreenshot_IsInvalid()
    {
        Assert.IsInstanceOfType<InvalidRole>(
            AppArguments.Parse(["--screenshot", "a.png", "--screenshot", "b.png"]));
    }

    [TestMethod]
    public void KnownSwitchFollowedByUnknown_IsInvalid()
    {
        Assert.IsInstanceOfType<InvalidRole>(AppArguments.Parse(["--smoke-test", "extra"]));
    }
}
