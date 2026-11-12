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
    public void Diagnose_IsRecognised()
    {
        Assert.IsInstanceOfType<DiagnoseCommand>(CliArguments.Parse(["--diagnose"]));
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
        // Escape, carriage return and line feed, built from code points so that this file
        // itself contains no control characters.
        string hostile = "bad" + (char)0x1B + "[31m" + (char)0x0D + (char)0x0A + new string('a', 200);

        var command = Assert.IsInstanceOfType<InvalidCommand>(CliArguments.Parse([hostile]));

        Assert.IsFalse(command.Message.Any(char.IsControl), "control characters must not be echoed");
        Assert.IsTrue(command.Message.Length < 80, "the echoed argument must be shortened");
        StringAssert.Contains(command.Message, "...");
    }

    [TestMethod]
    [DataRow(0x202E, DisplayName = "right-to-left override")]
    [DataRow(0x2066, DisplayName = "left-to-right isolate")]
    [DataRow(0x2028, DisplayName = "line separator")]
    [DataRow(0x2029, DisplayName = "paragraph separator")]
    [DataRow(0x200B, DisplayName = "zero-width space")]
    [DataRow(0x00E9, DisplayName = "non-ASCII letter")]
    [DataRow(0x007F, DisplayName = "delete")]
    public void EchoedArgument_IsLimitedToPrintableAscii(int codePoint)
    {
        string argument = "a" + (char)codePoint + "b";

        var command = Assert.IsInstanceOfType<InvalidCommand>(CliArguments.Parse([argument]));

        Assert.AreEqual("Unknown command 'a?b'.", command.Message);
    }

    [TestMethod]
    public void EchoedArgument_CutInsideSurrogatePair_LeavesNoLoneSurrogate()
    {
        // 39 ASCII characters, then a character outside the basic plane whose two halves
        // straddle the 40-character cut.
        string argument = new string('a', 39) + char.ConvertFromUtf32(0x1F600) + "tail";

        var command = Assert.IsInstanceOfType<InvalidCommand>(CliArguments.Parse([argument]));

        Assert.IsFalse(command.Message.Any(char.IsSurrogate), "no half surrogate pair may be echoed");
    }

    [TestMethod]
    public void Usage_ListsEveryCommand()
    {
        StringAssert.Contains(CliArguments.Usage, "--version");
        StringAssert.Contains(CliArguments.Usage, "--help");
        StringAssert.Contains(CliArguments.Usage, "--diagnose");
    }
}
