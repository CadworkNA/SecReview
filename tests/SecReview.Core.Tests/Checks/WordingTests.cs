using SecReview.Checks;

namespace SecReview.Tests.Checks;

[TestClass]
public sealed class WordingTests
{
    [TestMethod]
    [DataRow(0, "0 s")]
    [DataRow(45, "45 s")]
    [DataRow(60, "1 min")]
    [DataRow(900, "15 min")]
    [DataRow(920, "15 min 20 s")]
    [DataRow(3600, "1 h")]
    [DataRow(29_580, "8 h 13 min")]
    [DataRow(86_400, "1 day")]
    [DataRow(259_200, "3 days")]
    [DataRow(1_231_200, "14 days 6 h")]
    [DataRow(1_209_630, "14 days 30 s")]
    public void Duration_ShowsTheTwoLargestUnits_AndNeverRoundsUp(int seconds, string expected)
    {
        Assert.AreEqual(expected, Wording.Duration(TimeSpan.FromSeconds(seconds)));
    }

    [TestMethod]
    public void Duration_JustUnderAUnit_IsNotRoundedToIt()
    {
        Assert.AreEqual("13 days 23 h", Wording.Duration(TimeSpan.FromDays(14) - TimeSpan.FromSeconds(1)));
        Assert.AreEqual("14 min 59 s", Wording.Duration(TimeSpan.FromSeconds(899)));
        Assert.AreEqual("0 s", Wording.Duration(TimeSpan.FromSeconds(-5)));
    }

    [TestMethod]
    public void OneLine_LeavesOrdinaryTextAlone()
    {
        const string Text = "Registry for @company: plain HTTP (C:\\Users\\tester\\.npmrc, line 2)";

        Assert.AreSame(Text, Wording.OneLine(Text));
        Assert.AreEqual(string.Empty, Wording.OneLine(null));
        Assert.AreEqual("caf\u00E9 \u65E5\u672C \uD83D\uDE00", Wording.OneLine("caf\u00E9 \u65E5\u672C \uD83D\uDE00"), "letters of any language and character pairs stay");
    }

    [TestMethod]
    public void OneLine_TurnsLineBreaksAndControlCharactersIntoSpaces_AndDropsWhatIsNotShown()
    {
        Assert.AreEqual("a b  c d e", Wording.OneLine("a\nb\r\nc\td\0e"));
        Assert.AreEqual("a b c", Wording.OneLine("a\u2028b\u2029c"), "Unicode's own line and paragraph breaks");

        // A direction override would show "gpj.exe" as "exe.jpg"; zero-width characters hide a difference between two names.
        Assert.AreEqual("abcgpj.exe", Wording.OneLine("abc\u202Egpj.exe"));
        Assert.AreEqual("paypal", Wording.OneLine("pay\u200Bpal\uFEFF"));
    }

    [TestMethod]
    public void OneLine_CutsALongText_WithoutLeavingHalfACharacter()
    {
        string cut = Wording.OneLine(new string('a', 5000));
        Assert.AreEqual(Wording.MaximumLength, cut.Length);
        Assert.IsTrue(cut.EndsWith('\u2026'));

        Assert.AreEqual(Wording.MaximumLength, Wording.OneLine(new string('a', Wording.MaximumLength)).Length, "exactly the limit is not cut");
        string full = "\n" + new string('a', Wording.MaximumLength - 1);
        Assert.AreEqual(" " + new string('a', Wording.MaximumLength - 1), Wording.OneLine(full), "nor is a text that only needed cleaning");

        string pair = Wording.OneLine(new string('a', Wording.MaximumLength - 2) + "\uD83D\uDE00" + "bbb");
        Assert.IsFalse(pair.Any(char.IsSurrogate), "the pair that straddles the cut is left out whole");
    }

    [TestMethod]
    public void AResult_IsOneLineEach_WhateverACheckPutIntoIt()
    {
        var finding = Finding.Problem("Registry for @com\rpany", "plain\nHTTP", "HTTPS\u202E", "C:\\made-up\\.npmrc,\tline 2");
        CheckOutcome outcome = CheckOutcome.Fail("npm: registry for @com\rpany: plain HTTP.", finding);

        Assert.AreEqual("npm: registry for @com pany: plain HTTP.", outcome.Summary);
        Assert.AreEqual("Registry for @com pany", finding.Item);
        Assert.AreEqual("plain HTTP", finding.Found);
        Assert.AreEqual("HTTPS", finding.Expected);
        Assert.AreEqual("C:\\made-up\\.npmrc, line 2", finding.Source);
        Assert.IsNull(Finding.Note("a", "b").Source);
    }

    [TestMethod]
    public void JoinWithAnd_ReadsNaturally()
    {
        Assert.AreEqual(string.Empty, Wording.JoinWithAnd([]));
        Assert.AreEqual("A", Wording.JoinWithAnd(["A"]));
        Assert.AreEqual("A and B", Wording.JoinWithAnd(["A", "B"]));
        Assert.AreEqual("A, B and C", Wording.JoinWithAnd(["A", "B", "C"]));
    }

    [TestMethod]
    [DataRow("Hosts exempt from TLS checks", "hosts exempt from TLS checks")]
    [DataRow("Index \"internal\"", "index \"internal\"")]
    [DataRow("Off", "off")]
    [DataRow("TLS certificate checks", "TLS certificate checks", DisplayName = "an abbreviation")]
    [DataRow("PyPy download source", "PyPy download source", DisplayName = "a name with a capital inside")]
    [DataRow("Python download source", "Python download source", DisplayName = "a name")]
    [DataRow("A", "A", DisplayName = "too short to tell")]
    [DataRow("unsafe-best-match", "unsafe-best-match")]
    [DataRow("", "")]
    public void LowerFirst_LowersAnOrdinaryWord_AndLeavesNamesAlone(string text, string expected)
    {
        Assert.AreEqual(expected, Wording.LowerFirst(text));
    }

    [TestMethod]
    public void Date_IsTheSameEverywhere()
    {
        Assert.AreEqual("9 October 2029", Wording.Date(new DateOnly(2029, 10, 9)));
    }
}
