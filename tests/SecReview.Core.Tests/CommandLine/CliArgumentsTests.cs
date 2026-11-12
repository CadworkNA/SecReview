using SecReview.CommandLine;

namespace SecReview.Tests.CommandLine;

[TestClass]
public sealed class CliArgumentsTests
{
    [TestMethod]
    public void NoArguments_ShowsHelp()
    {
        Assert.IsInstanceOfType<HelpCommand>(CliArguments.Parse([]));
    }

    [TestMethod]
    [DataRow("--help")]
    [DataRow("-h")]
    [DataRow("/?")]
    public void HelpSwitches_ShowHelp(string argument)
    {
        Assert.IsInstanceOfType<HelpCommand>(CliArguments.Parse([argument]));
    }

    [TestMethod]
    public void Version_IsRecognised()
    {
        Assert.IsInstanceOfType<VersionCommand>(CliArguments.Parse(["--version"]));
    }

    [TestMethod]
    [DataRow("--Version")]
    [DataRow("version")]
    [DataRow("--report")]
    [DataRow("")]
    public void UnknownCommand_IsInvalid(string argument)
    {
        var command = Assert.IsInstanceOfType<InvalidCommand>(CliArguments.Parse([argument]));
        StringAssert.StartsWith(command.Message, "Unknown command");
    }

    [TestMethod]
    public void ExtraArgument_IsInvalid()
    {
        var command = Assert.IsInstanceOfType<InvalidCommand>(CliArguments.Parse(["--version", "x"]));
        Assert.AreEqual("Unexpected argument 'x'.", command.Message);
    }

    [TestMethod]
    public void EchoedArgument_IsShortenedAndHasNoControlCharacters()
    {
        string hostile = "bad\u001b[31m\r\n" + new string('a', 200);

        var command = Assert.IsInstanceOfType<InvalidCommand>(CliArguments.Parse([hostile]));

        Assert.IsFalse(command.Message.Any(char.IsControl), "control characters must not be echoed");
        Assert.IsTrue(command.Message.Length < 80, "the echoed argument must be shortened");
        StringAssert.Contains(command.Message, "...");
    }

    [TestMethod]
    public void Usage_ListsEveryCommand()
    {
        StringAssert.Contains(CliArguments.Usage, "--version");
        StringAssert.Contains(CliArguments.Usage, "--help");
    }
}
