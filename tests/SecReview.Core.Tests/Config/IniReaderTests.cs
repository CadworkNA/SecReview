using SecReview.Config;

namespace SecReview.Tests.Config;

[TestClass]
public sealed class IniReaderTests
{
    private static string Npm(string text) => IniReader.Read(text, IniDialect.Npm).Render();

    private static string Python(string text) => IniReader.Read(text, IniDialect.Python).Render();

    [TestMethod]
    public void AnNpmSettingsFile()
    {
        const string Text = """
            ; npm settings
            # another comment
            min-release-age=7
            registry = https://registry.npmjs.org/
            //registry.npmjs.org/:_authToken=${NPM_TOKEN}
            @company:registry=https://npm.example/
            strict-ssl=false
            quoted="a value"
            """;

        ConfigFile file = IniReader.Read(Text, IniDialect.Npm);

        Assert.AreEqual(
            "{min-release-age=\"7\", registry=\"https://registry.npmjs.org/\", //registry.npmjs.org/:_authToken=\"${NPM_TOKEN}\", " +
            "@company:registry=\"https://npm.example/\", strict-ssl=\"false\", quoted=\"a value\"}",
            file.Render());
        Assert.AreEqual(3, file.Root!["min-release-age"]!.Line);
    }

    [TestMethod]
    public void Npm_ListsAndRepeatedKeys()
    {
        Assert.AreEqual("{ca=[\"one\", \"two\"]}", Npm("ca[]=one\nca[] = two"));
        Assert.AreEqual("{a=[\"1\", \"2\"]}", Npm("a=1\na=2"), "a repeated key keeps every value");
        Assert.AreEqual("{a=\"\"}", Npm("a="));
        Assert.AreEqual("{a=\"x=y\"}", Npm("a=x=y"), "only the first = separates");
    }

    [TestMethod]
    public void Npm_Sections_AreRead_ThoughNpmFilesRarelyHaveThem()
    {
        Assert.AreEqual("{a=\"1\", section={b=\"2\"}}", Npm("a=1\n[section]\nb=2"));
    }

    [TestMethod]
    public void APipSettingsFile()
    {
        const string Text = """
            [global]
            uploaded-prior-to = P7D
            index-url = https://pypi.org/simple
            extra-index-url =
                https://packages.example/simple
                https://more.example/simple
            trusted-host: packages.example

            [install]
            only-binary = :all:
            """;

        ConfigFile file = IniReader.Read(Text, IniDialect.Python);

        Assert.AreEqual(
            "{global={uploaded-prior-to=\"P7D\", index-url=\"https://pypi.org/simple\", " +
            "extra-index-url=[\"https://packages.example/simple\", \"https://more.example/simple\"], trusted-host=\"packages.example\"}, " +
            "install={only-binary=\":all:\"}}",
            file.Render());
        Assert.AreEqual(2, file.Root!.Find("global", "uploaded-prior-to")!.Line);
    }

    [TestMethod]
    public void Python_AValueAndItsContinuation_BecomeAList()
    {
        Assert.AreEqual("{s={a=[\"one\", \"two\"]}}", Python("[s]\na = one\n    two"));
        Assert.AreEqual("{s={a=\"one\", b=\"two\"}}", Python("[s]\na = one\n\nb = two"));
    }

    [TestMethod]
    public void Python_QuotesAreKept_AsConfigparserDoes()
    {
        Assert.AreEqual("{s={a=\"\"x\"\"}}", Python("[s]\na = \"x\""));
    }

    [TestMethod]
    public void ASectionWrittenTwice_IsOneSection()
    {
        Assert.AreEqual("{s={a=\"1\", b=\"2\"}}", Python("[s]\na = 1\n[s]\nb = 2"));
    }

    [TestMethod]
    public void EmptyFiles_AndWindowsLineEndings()
    {
        Assert.AreEqual("{}", Npm(string.Empty));
        Assert.AreEqual("{}", Npm("; nothing\r\n\r\n"));
        Assert.AreEqual("{a=\"1\", b=\"2\"}", Npm("" + (char)0xFEFF + "a=1\r\nb=2\r\n"));
    }

    [TestMethod]
    [DataRow("just words", 1, DisplayName = "a line without =")]
    [DataRow("a=1\n[unclosed", 2, DisplayName = "an unclosed section")]
    [DataRow("=value", 1, DisplayName = "no name")]
    [DataRow("a=\"unclosed", 1, DisplayName = "an unclosed quote")]
    [DataRow("a=1\n[a]\nb=2", 2, DisplayName = "a name used for a setting and a section")]
    [DataRow("[]=x", 1, DisplayName = "a list with no name")]
    public void Npm_WhatIsNotUnderstood_StopsTheRead_WithTheLine(string text, int line)
    {
        ConfigFile file = IniReader.Read(text, IniDialect.Npm);

        Assert.IsFalse(file.IsOk, file.Render());
        Assert.AreEqual(line, file.ProblemLine, file.Problem);
    }

    [TestMethod]
    public void DamagedFiles_AlwaysEndWithAnAnswer()
    {
        const string Text = "; c\nmin-release-age=7\n//registry.npmjs.org/:_authToken=made-up\nca[]=one\nca[]=two\n[global]\nextra-index-url =\n    https://a.example\n    https://b.example\nquoted=\"x\"\n";
        var random = new Random(20261112);

        for (int round = 0; round < 4000; round++)
        {
            string damaged = ConfigTesting.Damage(Text, random);
            foreach (IniDialect dialect in Enum.GetValues<IniDialect>())
            {
                ConfigFile file = IniReader.Read(damaged, dialect);
                Assert.IsTrue(file.IsOk || (file.ProblemLine >= 1 && !string.IsNullOrWhiteSpace(file.Problem)), $"round {round}, {dialect}");
            }
        }
    }
}
