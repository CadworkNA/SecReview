using SecReview.Config;

namespace SecReview.Tests.Config;

[TestClass]
public sealed class GitConfigReaderTests
{
    /// <summary>Every setting as "section[.subsection].name=value" (a name written alone has no "=").</summary>
    private static string[] Read(string text)
    {
        GitConfigFile file = GitConfigReader.Read(text);
        Assert.IsTrue(file.IsOk, file.Describe());
        return [.. file.Settings!.Select(s =>
            $"{s.Section}{(s.Subsection is null ? string.Empty : "." + s.Subsection)}.{s.Name}{(s.Value is null ? string.Empty : "=" + s.Value)}")];
    }

    [TestMethod]
    public void AUsersSettingsFile()
    {
        const string Text =
            "# my settings\n" +
            "[user]\n" +
            "\tname = Someone\n" +
            "\temail = someone@example.test\n" +
            "[core]\n" +
            "\tautocrlf = true ; line endings\n" +
            "\teditor = \"code --wait\"\n" +
            "[http \"https://git.example.test/\"]\n" +
            "\tsslVerify = false\n" +
            "[credential]\n" +
            "\thelper = manager\n";

        GitConfigFile file = GitConfigReader.Read(Text);

        CollectionAssert.AreEqual(
            new[]
            {
                "user.name=Someone", "user.email=someone@example.test", "core.autocrlf=true", "core.editor=code --wait",
                "http.https://git.example.test/.sslverify=false", "credential.helper=manager",
            },
            Read(Text));
        Assert.AreEqual(9, file.Settings![4].Line);
    }

    [TestMethod]
    public void NamesAreLowered_SubsectionsKeepTheirCase_AndTheOldDottedFormLowersBoth()
    {
        CollectionAssert.AreEqual(new[] { "remote.Origin.url=x" }, Read("[Remote \"Origin\"]\n\tURL = x"));
        CollectionAssert.AreEqual(new[] { "remote.origin.url=x" }, Read("[Remote.Origin]\n\turl = x"));
    }

    [TestMethod]
    public void ANameAlone_IsTrue_AndRepeatedSettingsAreAllKept()
    {
        GitConfigFile file = GitConfigReader.Read("[core]\n\tbare\n[safe]\n\tdirectory = a\n\tdirectory = *\n\tdirectory =\n");

        Assert.IsNull(file.Settings![0].Value);
        Assert.IsTrue(file.Settings[0].AsBoolean);
        CollectionAssert.AreEqual(new[] { "core.bare", "safe.directory=a", "safe.directory=*", "safe.directory=" }, Read("[core]\n\tbare\n[safe]\n\tdirectory = a\n\tdirectory = *\n\tdirectory =\n"));
    }

    [TestMethod]
    [DataRow("true", true)]
    [DataRow("Yes", true)]
    [DataRow("on", true)]
    [DataRow("1", true)]
    [DataRow("false", false)]
    [DataRow("NO", false)]
    [DataRow("off", false)]
    [DataRow("0", false)]
    public void YesAndNo_AreReadAsGitReadsThem(string value, bool expected)
    {
        Assert.AreEqual(expected, GitConfigReader.Read($"[http]\n\tsslVerify = {value}").Settings![0].AsBoolean);
    }

    [TestMethod]
    public void AValueThatIsNotYesOrNo_IsNeither()
    {
        Assert.IsNull(GitConfigReader.Read("[core]\n\tfsmonitor = C:/tools/watch.exe").Settings![0].AsBoolean);
    }

    [TestMethod]
    public void Values_Quotes_Escapes_Comments_AndContinuedLines()
    {
        const char Backslash = (char)92;

        CollectionAssert.AreEqual(new[] { "a.b=one two" }, Read("[a]\n\tb =   one two   "));
        CollectionAssert.AreEqual(new[] { "a.b= kept " }, Read("[a]\n\tb = \" kept \""));
        CollectionAssert.AreEqual(new[] { "a.b=x # not a comment" }, Read("[a]\n\tb = \"x # not a comment\" # a comment"));
        CollectionAssert.AreEqual(new[] { "a.b=x" }, Read("[a]\n\tb = x ; a comment"));
        CollectionAssert.AreEqual(new[] { "a.b=C:" + Backslash + "tools" }, Read($"[a]\n\tb = C:{Backslash}{Backslash}tools"));
        CollectionAssert.AreEqual(new[] { "a.b=say \"hi\"" }, Read($"[a]\n\tb = say {Backslash}\"hi{Backslash}\""));
        CollectionAssert.AreEqual(new[] { "a.b=one two", "a.c=3" }, Read($"[a]\n\tb = one {Backslash}\ntwo\n\tc = 3"));
    }

    [TestMethod]
    public void ASettingOnTheHeadersLine_AndAnEmptyFile()
    {
        CollectionAssert.AreEqual(new[] { "a.b=1" }, Read("[a] b = 1"));
        CollectionAssert.AreEqual(Array.Empty<string>(), Read(string.Empty));
        CollectionAssert.AreEqual(new[] { "a.b=1" }, Read("" + (char)0xFEFF + "[a]\r\n\tb = 1\r\n"));
    }

    [TestMethod]
    [DataRow("name = value", 1, DisplayName = "a setting before any section")]
    [DataRow("[a]\n\t= value", 2, DisplayName = "no name")]
    [DataRow("[a]\n\tb c", 2, DisplayName = "words without =")]
    [DataRow("[a\n\tb = 1", 1, DisplayName = "an unclosed section")]
    [DataRow("[a \"sub]\n\tb = 1", 1, DisplayName = "an unclosed subsection")]
    [DataRow("[]\n\tb = 1", 1, DisplayName = "a section without a name")]
    [DataRow("[a]\n\tb = \"unclosed", 2, DisplayName = "an unclosed quote")]
    [DataRow("[a]\n\t1b = x", 2, DisplayName = "a name that starts with a digit")]
    public void WhatIsNotUnderstood_StopsTheRead_WithTheLine(string text, int line)
    {
        GitConfigFile file = GitConfigReader.Read(text);

        Assert.IsFalse(file.IsOk);
        Assert.AreEqual(line, file.ProblemLine, file.Problem);
        StringAssert.StartsWith(file.Describe(), $"could not evaluate (line {line}): ");
    }

    [TestMethod]
    public void AnUnknownEscape_OrAValueContinuedPastTheEnd_StopsTheRead()
    {
        const char Backslash = (char)92;

        Assert.IsFalse(GitConfigReader.Read($"[a]\n\tb = bad {Backslash}q").IsOk);
        Assert.IsFalse(GitConfigReader.Read($"[a]\n\tb = one {Backslash}").IsOk);
    }

    [TestMethod]
    public void DamagedFiles_AlwaysEndWithAnAnswer()
    {
        const string Text = "# c\n[user]\n\tname = Someone\n[http \"https://git.example.test/\"]\n\tsslVerify = false\n[core]\n\tbare\n\teditor = \"code --wait\" ; note\n[include]\n\tpath = ~/other\n";
        var random = new Random(20261112);

        for (int round = 0; round < 4000; round++)
        {
            GitConfigFile file = GitConfigReader.Read(ConfigTesting.Damage(Text, random));
            Assert.IsTrue(file.IsOk || (file.ProblemLine >= 1 && !string.IsNullOrWhiteSpace(file.Problem)), $"round {round}");
        }
    }
}
