using System.Text;
using SecReview.Config;

namespace SecReview.Tests.Config;

[TestClass]
public sealed class MarkupReaderTests
{
    /// <summary>An element as "name[attr=value, …]{children}" with its text after ":" when it has any.</summary>
    private static string Render(MarkupElement element)
    {
        var text = new StringBuilder(element.Name);
        if (element.Attributes.Count > 0)
        {
            text.Append('[').AppendJoin(", ", element.Attributes.Select(a => $"{a.Key}={a.Value}")).Append(']');
        }

        if (element.Text.Length > 0)
        {
            text.Append(':').Append(element.Text);
        }

        if (element.Children.Count > 0)
        {
            text.Append('{').AppendJoin(' ', element.Children.Select(Render)).Append('}');
        }

        return text.ToString();
    }

    private static string Read(string xml)
    {
        MarkupFile file = MarkupReader.Read(xml);
        Assert.IsTrue(file.IsOk, file.Describe());
        return Render(file.Root!);
    }

    [TestMethod]
    public void ANuGetSettingsFile()
    {
        const string Xml = """
            <?xml version="1.0" encoding="utf-8"?>
            <configuration>
              <!-- one source -->
              <packageSources>
                <clear />
                <add key="nuget.org" value="https://api.nuget.org/v3/index.json" protocolVersion="3" />
              </packageSources>
            </configuration>
            """;

        MarkupFile file = MarkupReader.Read(Xml);

        Assert.AreEqual(
            "configuration{packageSources{clear add[key=nuget.org, value=https://api.nuget.org/v3/index.json, protocolVersion=3]}}",
            Render(file.Root!));
        Assert.AreEqual(6, file.Root!.Children[0].Children[1].Line);
        Assert.AreEqual("nuget.org", file.Root.Children[0].Children[1].Attribute("key"));
        Assert.IsNull(file.Root.Children[0].Children[1].Attribute("KEY"), "attribute names are matched exactly, as the tools do");
    }

    [TestMethod]
    public void Text_Entities_Cdata_AndBothKindsOfQuotes()
    {
        Assert.AreEqual("a:x < y & z", Read("<a> x &lt; y &amp; z </a>"));
        Assert.AreEqual("a[b=say \"hi\", c=it's]", Read("<a b='say \"hi\"' c=\"it&apos;s\" />"));
        Assert.AreEqual("a:A B", Read("<a>&#65; &#x42;</a>"));
        Assert.AreEqual("a:<kept & raw>", Read("<a><![CDATA[<kept & raw>]]></a>"));
        Assert.AreEqual("a{b:one c:two}", Read("<a><b>one</b><!-- note --><c>two</c></a>"));
    }

    [TestMethod]
    public void Prefixes_AreDropped_AndAByteOrderMarkIsFine()
    {
        Assert.AreEqual("settings[xmlns=urn:x, schemaLocation=y]{server}", Read("<m:settings xmlns=\"urn:x\" xsi:schemaLocation=\"y\"><m:server/></m:settings>"));
        Assert.AreEqual("a", Read("" + (char)0xFEFF + "<a/>\r\n"));
    }

    [TestMethod]
    public void ANameEncodedForXml_IsDecoded()
    {
        Assert.AreEqual("company feed", MarkupReader.DecodeName("company_x0020_feed"));
        Assert.AreEqual("plain_name", MarkupReader.DecodeName("plain_name"));
        Assert.AreEqual("a_xZZZZ_b", MarkupReader.DecodeName("a_xZZZZ_b"));
    }

    [TestMethod]
    [DataRow("<!DOCTYPE a [<!ENTITY x SYSTEM \"file:///C:/Windows/win.ini\">]>\n<a>&x;</a>", 1, DisplayName = "a document type")]
    [DataRow("<a>&unknown;</a>", 1, DisplayName = "an entity of the file's own")]
    [DataRow("<a>\n<b>\n</a>", 3, DisplayName = "a tag closed out of order")]
    [DataRow("<a>\n<b>", 2, DisplayName = "an element left open")]
    [DataRow("<a/>\n<b/>", 2, DisplayName = "two root elements")]
    [DataRow("text", 1, DisplayName = "no element at all")]
    [DataRow("", 1, DisplayName = "an empty file")]
    [DataRow("<a b=1/>", 1, DisplayName = "an attribute without quotes")]
    [DataRow("<a b=\"1\" b=\"2\"/>", 1, DisplayName = "an attribute twice")]
    [DataRow("<a b=\"unclosed/>", 1, DisplayName = "an unclosed attribute")]
    [DataRow("<a><!-- never closed</a>", 1, DisplayName = "an unclosed comment")]
    [DataRow("<a>x</a> trailing", 1, DisplayName = "text after the root")]
    [DataRow("<1a/>", 1, DisplayName = "a name that starts with a digit")]
    [DataRow("<a>&#0;</a>", 1, DisplayName = "a character code that is no character")]
    public void WhatIsNotUnderstood_StopsTheRead_WithTheLine(string xml, int line)
    {
        MarkupFile file = MarkupReader.Read(xml);

        Assert.IsFalse(file.IsOk);
        Assert.AreEqual(line, file.ProblemLine, file.Problem);
        StringAssert.StartsWith(file.Describe(), $"could not evaluate (line {line}): ");
    }

    [TestMethod]
    public void WhatIsNotUnderstood_IsDescribedWithoutQuotingTheFile()
    {
        MarkupFile entity = MarkupReader.Read("<settings><password>made&upsecret;x</password></settings>");
        Assert.IsFalse(entity.IsOk);
        Assert.IsFalse(entity.Problem!.Contains("upsecret", StringComparison.Ordinal));

        MarkupFile tag = MarkupReader.Read("<a><madeupname></a>");
        Assert.IsFalse(tag.IsOk);
        Assert.IsFalse(tag.Problem!.Contains("madeupname", StringComparison.Ordinal));
    }

    [TestMethod]
    public void AnElementWithFarTooManyAttributes_IsRefused_NotSearchedAgainAndAgain()
    {
        string attributes = string.Concat(Enumerable.Range(0, 5000).Select(i => $" a{i}='x'"));

        Assert.IsFalse(MarkupReader.Read($"<a{attributes} />").IsOk);
    }

    [TestMethod]
    public void VeryDeepNesting_IsRefused()
    {
        string deep = string.Concat(Enumerable.Repeat("<a>", 5000)) + string.Concat(Enumerable.Repeat("</a>", 5000));

        MarkupFile file = MarkupReader.Read(deep);

        Assert.IsFalse(file.IsOk);
        StringAssert.Contains(file.Problem, "nested too deeply");
    }

    [TestMethod]
    public void DamagedFiles_AlwaysEndWithAnAnswer()
    {
        const string Xml = "<?xml version=\"1.0\"?>\n<configuration>\n  <!-- c -->\n  <packageSources>\n    <clear />\n    <add key=\"a b\" value='https://x.example/?q=1&amp;r=2' />\n  </packageSources>\n  <t><![CDATA[x]]></t>\n</configuration>\n";
        var random = new Random(20261112);

        for (int round = 0; round < 4000; round++)
        {
            MarkupFile file = MarkupReader.Read(ConfigTesting.Damage(Xml, random));
            Assert.IsTrue(file.IsOk || (file.ProblemLine >= 1 && !string.IsNullOrWhiteSpace(file.Problem)), $"round {round}");
        }
    }
}
