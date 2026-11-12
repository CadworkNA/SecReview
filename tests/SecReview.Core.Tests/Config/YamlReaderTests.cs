using SecReview.Config;

namespace SecReview.Tests.Config;

[TestClass]
public sealed class YamlReaderTests
{
    private static string Read(string yaml) => YamlReader.Read(yaml).Render();

    [TestMethod]
    public void AGlobalSettingsFile_LikePnpmWrites()
    {
        const string Yaml = """
            # written by pnpm config set
            minimumReleaseAge: 10080
            storeDir: C:\Users\tester\scoop\persist\pnpm\store
            trustPolicy: no-downgrade
            strictDepBuilds: true
            minimumReleaseAgeExclude:
              - '@types/*'
              - "left-pad"
            """;

        ConfigFile file = YamlReader.Read(Yaml);

        Assert.AreEqual(
            "{minimumReleaseAge=10080, storeDir=\"C:\\Users\\tester\\scoop\\persist\\pnpm\\store\", trustPolicy=\"no-downgrade\", " +
            "strictDepBuilds=true, minimumReleaseAgeExclude=[\"@types/*\", \"left-pad\"]}",
            file.Render());
        Assert.AreEqual(2, file.Root!["minimumReleaseAge"]!.Line);
        Assert.AreEqual(10080L, ((ConfigScalar)file.Root["minimumReleaseAge"]!).AsNumber);
    }

    [TestMethod]
    public void NestedMappings_AsPnpmStoresSignInTokens()
    {
        const string Yaml = """
            _auth:
              https://registry.npmjs.org:
                "@":
                  authToken: made-up-token
                "@org":
                  authToken: another-made-up-token
            minimumReleaseAge: 10080
            """;

        ConfigFile file = YamlReader.Read(Yaml);

        Assert.AreEqual(
            "{_auth={https://registry.npmjs.org={@={authToken=\"made-up-token\"}, @org={authToken=\"another-made-up-token\"}}}, minimumReleaseAge=10080}",
            file.Render());
        Assert.AreEqual(4, file.Root!.Find("_auth", "https://registry.npmjs.org", "@", "authToken")!.Line);
    }

    [TestMethod]
    public void AYarnSettingsFile()
    {
        const string Yaml = """
            npmMinimalAgeGate: "7d"
            enableScripts: false
            npmScopes:
              company:
                npmRegistryServer: "https://npm.example"
                npmAuthToken: ${NPM_TOKEN}
            unsafeHttpWhitelist: ["localhost", "*.internal.example"]
            """;

        Assert.AreEqual(
            "{npmMinimalAgeGate=\"7d\", enableScripts=false, npmScopes={company={npmRegistryServer=\"https://npm.example\", npmAuthToken=\"${NPM_TOKEN}\"}}, " +
            "unsafeHttpWhitelist=[\"localhost\", \"*.internal.example\"]}",
            Read(Yaml));
    }

    [TestMethod]
    public void Lists_AtTheKeysOwnIndentation_AndOfMappings()
    {
        Assert.AreEqual("{a=[\"x\", \"y\"], b=1}", Read("a:\n- x\n- y\nb: 1"));
        Assert.AreEqual("{items=[{name=\"one\", value=1}, {name=\"two\"}]}", Read("items:\n  - name: one\n    value: 1\n  - name: two\n"));
        Assert.AreEqual("{a=[[\"x\", \"y\"], {k=\"v\"}]}", Read("a:\n  - [x, y]\n  - {k: v}"));
        Assert.AreEqual("{a=[<null>, \"x\"]}", Read("a:\n  -\n  - x"));
    }

    [TestMethod]
    public void OneLineListsAndMappings()
    {
        Assert.AreEqual("{a=[1, \"two\", true], b={x=1, y=\"z\"}, c=[], d={}}", Read("a: [1, two, true]\nb: {x: 1, \"y\": z}\nc: []\nd: {}"));
        Assert.AreEqual("{a=[[1, 2], {k=[3]}]}", Read("a: [[1, 2], {k: [3]}]"));
    }

    [TestMethod]
    public void PlainValues_GetTheKindYamlGivesThem()
    {
        Assert.AreEqual(
            "{a=10080, b=true, c=false, d=<null>, e=<null>, f=<1.5>, g=\"7d\", h=\"no-downgrade\", i=\"0755\", j=-3}",
            Read("a: 10080\nb: true\nc: False\nd: null\ne:\nf: 1.5\ng: 7d\nh: no-downgrade\ni: 0755\nj: -3"));
        Assert.AreEqual("{a=\"true\", b=\"10080\"}", Read("a: \"true\"\nb: '10080'"), "quoted values are text");
    }

    [TestMethod]
    public void QuotesAndComments()
    {
        Assert.AreEqual("{a=\"it's\", b=\"say \"hi\"\ttab\", c=\"# not a comment\", d=\"x#y\", e=\"http://host:80/a\"}",
            Read("a: 'it''s'\nb: \"say \\\"hi\\\"\\ttab\"\nc: '# not a comment' # a comment\nd: x#y\ne: http://host:80/a # trailing"));
        Assert.AreEqual("{key with spaces=1, quoted: key=2}", Read("key with spaces: 1\n\"quoted: key\": 2"));
    }

    [TestMethod]
    public void AnEmptyFile_ADocumentStart_AndWindowsLineEndings()
    {
        Assert.AreEqual("{}", Read(string.Empty));
        Assert.AreEqual("{}", Read("# only a comment\n\n"));
        Assert.AreEqual("{a=1, b={c=2}}", Read("---\r\na: 1\r\nb:\r\n  c: 2\r\n"));
        Assert.AreEqual("{a=1}", Read("a: 1\n...\n"));
    }

    [TestMethod]
    [DataRow("a: 1\na: 2", 2, DisplayName = "a key twice")]
    [DataRow("a: &anchor 1", 1, DisplayName = "an anchor")]
    [DataRow("a: 1\nb: *anchor", 2, DisplayName = "an alias")]
    [DataRow("a: !!str 1", 1, DisplayName = "a tag")]
    [DataRow("a: |\n  text\n", 1, DisplayName = "block text")]
    [DataRow("a: >\n  text\n", 1, DisplayName = "folded text")]
    [DataRow("a: one\n  two", 2, DisplayName = "a value continued on the next line")]
    [DataRow("a: 1\n---\nb: 2", 2, DisplayName = "a second document")]
    [DataRow("a:\n\tb: 1", 2, DisplayName = "a tab as indentation")]
    [DataRow("a:\n    b: 1\n  c: 2", 3, DisplayName = "indentation that matches no level")]
    [DataRow("a: 1\n  b: 2", 2, DisplayName = "unexpected indentation")]
    [DataRow("just a line", 1, DisplayName = "not a setting")]
    [DataRow("- a\n- b", 1, DisplayName = "a list at the top")]
    [DataRow("a: [1, 2", 1, DisplayName = "an unclosed list")]
    [DataRow("a: {x: 1", 1, DisplayName = "an unclosed mapping")]
    [DataRow("a: \"unclosed", 1, DisplayName = "an unclosed quote")]
    [DataRow("a: \"x\" y", 1, DisplayName = "text after a quoted value")]
    [DataRow("<<: {a: 1}", 1, DisplayName = "a merge key")]
    [DataRow("? complex\n: value", 1, DisplayName = "a complex key")]
    [DataRow("a:\n  - x\n  b: 1", 3, DisplayName = "a setting among list items")]
    [DataRow("a: \"bad \\q\"", 1, DisplayName = "an unknown escape")]
    public void WhatThisReaderDoesNotRead_StopsTheRead_WithTheLine(string yaml, int line)
    {
        ConfigFile file = YamlReader.Read(yaml);

        Assert.IsFalse(file.IsOk, file.Render());
        Assert.AreEqual(line, file.ProblemLine, file.Problem);
    }

    [TestMethod]
    public void VeryDeepNesting_IsRefused_NotAStackOverflow()
    {
        Assert.IsFalse(YamlReader.Read("a: " + new string('[', 5000) + new string(']', 5000)).IsOk);

        string deep = string.Concat(Enumerable.Range(0, 200).Select(i => new string(' ', i) + "k:\n"));
        Assert.IsFalse(YamlReader.Read(deep).IsOk);
    }

    [TestMethod]
    public void DamagedFiles_AlwaysEndWithAnAnswer()
    {
        const string Yaml = """
            # settings
            minimumReleaseAge: 10080
            trustPolicy: "no-downgrade"
            minimumReleaseAgeExclude:
              - '@types/*'
              - left-pad
            _auth:
              https://registry.npmjs.org:
                "@":
                  authToken: made-up-token
            registries: {default: "https://registry.npmjs.org/", "@org": https://npm.example}
            list: [a, "b", 3]
            items:
              - name: one
                value: 1
              - name: two
            """;
        var random = new Random(20261112);

        for (int round = 0; round < 4000; round++)
        {
            ConfigFile file = YamlReader.Read(ConfigTesting.Damage(Yaml, random));

            Assert.IsTrue(file.IsOk || (file.ProblemLine >= 1 && !string.IsNullOrWhiteSpace(file.Problem)), $"round {round}");
        }
    }
}
