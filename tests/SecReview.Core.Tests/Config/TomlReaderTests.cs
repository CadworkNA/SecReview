using SecReview.Config;

namespace SecReview.Tests.Config;

[TestClass]
public sealed class TomlReaderTests
{
    private static string Read(string toml) => TomlReader.Read(toml).Render();

    [TestMethod]
    public void AUserSettingsFile_LikeUvWrites()
    {
        const string Toml = """
            # uv settings
            exclude-newer = "7 days"
            python-downloads = "manual"
            link-mode = "copy"
            compile-bytecode = true

            [pip]
            index-strategy = "first-index"
            """;

        ConfigFile file = TomlReader.Read(Toml);

        Assert.AreEqual(
            "{exclude-newer=\"7 days\", python-downloads=\"manual\", link-mode=\"copy\", compile-bytecode=true, pip={index-strategy=\"first-index\"}}",
            file.Render());
        Assert.AreEqual(2, file.Root!["exclude-newer"]!.Line);
        Assert.AreEqual(8, file.Root.Find("pip", "index-strategy")!.Line);
    }

    [TestMethod]
    public void ArraysOfTables_AsUvIndexesAndCredentials()
    {
        const string Toml = """
            [[index]]
            name = "internal"
            url = "https://packages.example/simple"
            ignore-error-codes = [401, 403]

            [[index]]
            name = "pypi"
            url = "https://pypi.org/simple"
            default = true
            """;

        Assert.AreEqual(
            "{index=[{name=\"internal\", url=\"https://packages.example/simple\", ignore-error-codes=[401, 403]}, " +
            "{name=\"pypi\", url=\"https://pypi.org/simple\", default=true}]}",
            Read(Toml));
    }

    [TestMethod]
    public void InlineTables_DottedKeys_AndQuotedKeys()
    {
        Assert.AreEqual("{exclude-newer-package={numpy=false, torch=\"3 days\"}}", Read("exclude-newer-package = { numpy = false, torch = \"3 days\" }"));
        Assert.AreEqual("{strategy={exclude-newer=\"7d\"}}", Read("strategy.exclude-newer = \"7d\""));
        Assert.AreEqual("{a={b={c=1, d=2}}}", Read("a.b.c = 1\na.b.d = 2"));
        Assert.AreEqual("{my key={x.y=1}}", Read("\"my key\".'x.y' = 1"));
        Assert.AreEqual("{install={minimumReleaseAge=604800}}", Read("[install]\nminimumReleaseAge = 604800 # one week\n"));
        Assert.AreEqual("{solver={min-release-age=7}}", Read("[solver]\nmin-release-age = 7"));
        Assert.AreEqual("{a={}}", Read("a = {}"));
    }

    [TestMethod]
    public void TablesAndSubTables_InAnyOrder()
    {
        Assert.AreEqual("{a={b={x=1}, y=2}}", Read("[a.b]\nx = 1\n[a]\ny = 2"));
        Assert.AreEqual("{tool={uv={exclude-newer=\"7 days\", pip={x=1}}}}", Read("[tool.uv]\nexclude-newer = \"7 days\"\n[tool.uv.pip]\nx = 1"));
        Assert.AreEqual("{fruit=[{name=\"apple\", variety=[{name=\"red\"}]}]}", Read("[[fruit]]\nname = \"apple\"\n[[fruit.variety]]\nname = \"red\""));
    }

    [TestMethod]
    public void Strings_OfAllFourKinds()
    {
        Assert.AreEqual("{a=\"tab\there \"quoted\" é\"}", Read("a = \"tab\\there \\\"quoted\\\" \\u00E9\""));
        Assert.AreEqual("{a=\"C:\\Users\\name\"}", Read("a = 'C:\\Users\\name'"));
        Assert.AreEqual("{a=\"one\ntwo\"}", Read("a = \"\"\"\none\ntwo\"\"\""));
        Assert.AreEqual("{a=\"one two\"}", Read("a = \"\"\"one \\\n   two\"\"\""));
        Assert.AreEqual("{a=\"raw\\n\ntext\"}", Read("a = '''raw\\n\ntext'''"));
        Assert.AreEqual("{a=\"say \"\"hi\"\"\"}", Read("a = \"\"\"say \"\"hi\"\"\"\"\""));
        Assert.AreEqual("{a=\"\"}", Read("a = \"\""));
    }

    [TestMethod]
    public void NumbersBooleansAndDates()
    {
        Assert.AreEqual("{a=10080, b=-1, c=1_000, d=true, e=false}", Read("a = 10080\nb = -1\nc = 1_000\nd = true\ne = false"));
        Assert.AreEqual(1000L, ((ConfigScalar)TomlReader.Read("c = 1_000").Root!["c"]!).AsNumber);
        Assert.AreEqual("{a=<2026-11-12T00:00:00Z>, b=<1.5>, c=<0x1F>}", Read("a = 2026-11-12T00:00:00Z\nb = 1.5\nc = 0x1F"));
        Assert.IsNull(((ConfigScalar)TomlReader.Read("a = \"7\"").Root!["a"]!).AsNumber, "text is not a number");
    }

    [TestMethod]
    public void Lists_OverSeveralLines_WithCommentsAndTrailingComma()
    {
        Assert.AreEqual(
            "{allow-insecure-host=[\"a.example\", \"b.example:8080\"]}",
            Read("allow-insecure-host = [\n  \"a.example\", # first\n  \"b.example:8080\",\n]\n"));
        Assert.AreEqual("{a=[[1, 2], [\"x\"], {k=1}]}", Read("a = [[1, 2], [\"x\"], {k = 1}]"));
        Assert.AreEqual("{a=[]}", Read("a = []"));
    }

    [TestMethod]
    public void AnEmptyFile_OrOnlyComments_IsAnEmptySetOfSettings()
    {
        Assert.AreEqual("{}", Read(string.Empty));
        Assert.AreEqual("{}", Read("# nothing here\r\n\r\n   # still nothing\r\n"));
    }

    [TestMethod]
    public void WindowsLineEndings_AreRead()
    {
        Assert.AreEqual("{a=1, t={b=\"x\"}}", Read("a = 1\r\n[t]\r\nb = \"x\"\r\n"));
    }

    [TestMethod]
    [DataRow("a = 1\na = 2", 2, DisplayName = "a key twice")]
    [DataRow("[t]\nx = 1\n[t]\ny = 2", 3, DisplayName = "a table twice")]
    [DataRow("a = { x = 1 }\na.y = 2", 2, DisplayName = "adding to an inline table")]
    [DataRow("a = [1]\n[[a]]\nx = 1", 2, DisplayName = "extending a value list with a table")]
    [DataRow("a = 1\n[a]\nx = 1", 2, DisplayName = "a value reopened as a table")]
    [DataRow("a = 1\n[a.b]\nx = 1", 2, DisplayName = "a table under a value")]
    [DataRow("a = \"unclosed", 1, DisplayName = "an unclosed string")]
    [DataRow("a = 'unclosed", 1, DisplayName = "an unclosed literal string")]
    [DataRow("ok = 1\na = \"\"\"never closed\n\n", 2, DisplayName = "an unclosed multi-line string")]
    [DataRow("a = [1, 2", 1, DisplayName = "an unclosed list")]
    [DataRow("a = { x = 1", 1, DisplayName = "an unclosed inline table")]
    [DataRow("a = 7 days", 1, DisplayName = "text without quotes")]
    [DataRow("a = yes", 1, DisplayName = "a word that is not a TOML value")]
    [DataRow("a =", 1, DisplayName = "no value")]
    [DataRow("= 1", 1, DisplayName = "no key")]
    [DataRow("a b = 1", 1, DisplayName = "a key with a space")]
    [DataRow("a = 1 b = 2", 1, DisplayName = "two settings on a line")]
    [DataRow("[t", 1, DisplayName = "an unclosed table header")]
    [DataRow("[[t]", 1, DisplayName = "a half-closed array header")]
    [DataRow("a = \"bad \\q escape\"", 1, DisplayName = "an unknown escape")]
    [DataRow("a = \"\\uZZZZ\"", 1, DisplayName = "a bad character code")]
    [DataRow("a = 01", 1, DisplayName = "a number with a leading zero")]
    [DataRow("x = 1\ny = 2\njust some words\n", 3, DisplayName = "a line that is not a setting")]
    public void WhatIsNotValid_StopsTheRead_WithTheLine(string toml, int line)
    {
        ConfigFile file = TomlReader.Read(toml);

        Assert.IsFalse(file.IsOk, file.Render());
        Assert.AreEqual(line, file.ProblemLine, file.Problem);
        StringAssert.StartsWith(file.Describe(), $"could not evaluate (line {line}): ");
    }

    [TestMethod]
    [DataRow("UFFFFFFFF", DisplayName = "a code too large for a number with a sign")]
    [DataRow("U00110000", DisplayName = "a code past the last character")]
    [DataRow("uD800", DisplayName = "half of a surrogate pair")]
    public void ACharacterCodeThatIsNotACharacter_StopsTheRead(string code)
    {
        const char Backslash = (char)92;

        ConfigFile file = TomlReader.Read($"a = \"{Backslash}{code}\"");

        Assert.IsFalse(file.IsOk, file.Render());
        Assert.AreEqual(1, file.ProblemLine);
        Assert.IsFalse(YamlReader.Read($"a: \"{Backslash}{code}\"").IsOk, "the YAML reader refuses it too");
    }

    [TestMethod]
    public void VeryDeepNesting_IsRefused_NotAStackOverflow()
    {
        ConfigFile file = TomlReader.Read("a = " + new string('[', 5000) + new string(']', 5000));

        Assert.IsFalse(file.IsOk);
        StringAssert.Contains(file.Problem, "nested too deeply");
    }

    [TestMethod]
    public void DamagedFiles_AlwaysEndWithAnAnswer()
    {
        const string Toml = """"
            exclude-newer = "7 days"
            allow-insecure-host = ["a.example", 'b.example']
            exclude-newer-package = { numpy = false, "big pkg" = "3 days" }
            text = '''literal
            lines'''
            more = """basic \
              joined"""

            [[index]]
            name = "internal"
            url = "https://packages.example/simple"
            ignore-error-codes = [401, 403]

            [pip]
            require-hashes = true
            dotted.key = 1_000
            """";
        var random = new Random(20261112);

        for (int round = 0; round < 4000; round++)
        {
            ConfigFile file = TomlReader.Read(ConfigTesting.Damage(Toml, random));

            Assert.IsTrue(file.IsOk || (file.ProblemLine >= 1 && !string.IsNullOrWhiteSpace(file.Problem)), $"round {round}");
        }
    }
}
