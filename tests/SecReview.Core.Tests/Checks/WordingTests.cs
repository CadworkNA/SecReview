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
