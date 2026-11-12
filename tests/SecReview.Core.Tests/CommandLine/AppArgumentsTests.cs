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
