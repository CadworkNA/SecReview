using SecReview.CommandLine;

namespace SecReview.Tests.CommandLine;

[TestClass]
public sealed class AppArgumentsTests
{
    [TestMethod]
    public void NoArguments_ShowsTheWindow()
    {
        var role = Assert.IsInstanceOfType<UiRole>(AppArguments.Parse([]));
        Assert.IsFalse(role.SmokeTest);
    }

    [TestMethod]
    public void SmokeTestSwitch_ShowsTheWindowInSmokeTestMode()
    {
        var role = Assert.IsInstanceOfType<UiRole>(AppArguments.Parse(["--smoke-test"]));
        Assert.IsTrue(role.SmokeTest);
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
    public void RepeatedSwitch_IsInvalid()
    {
        Assert.IsInstanceOfType<InvalidRole>(AppArguments.Parse(["--smoke-test", "--smoke-test"]));
    }

    [TestMethod]
    public void KnownSwitchFollowedByUnknown_IsInvalid()
    {
        Assert.IsInstanceOfType<InvalidRole>(AppArguments.Parse(["--smoke-test", "extra"]));
    }
}
