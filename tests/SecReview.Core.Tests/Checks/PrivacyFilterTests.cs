using SecReview.Checks;

namespace SecReview.Tests.Checks;

[TestClass]
public sealed class PrivacyFilterTests
{
    private static readonly PrivacyFilter Filter = new(@"C:\Users\alice", "alice", "DESKTOP-EXAMPLE");

    [TestMethod]
    [DataRow(@"Access to the path 'C:\Users\alice\.npmrc' is denied.", @"Access to the path '%USERPROFILE%\.npmrc' is denied.")]
    [DataRow(@"c:\users\ALICE\AppData\Roaming\uv\uv.toml", @"%USERPROFILE%\AppData\Roaming\uv\uv.toml")]
    [DataRow(@"C:\Users\bob\.gitconfig", @"C:\Users\<user>\.gitconfig")]
    [DataRow("Owner: alice", "Owner: <user>")]
    [DataRow(@"DESKTOP-EXAMPLE\alice", @"<computer>\<user>")]
    [DataRow("Found on desktop-example.", "Found on <computer>.")]
    public void Names_AreReplaced(string text, string expected)
    {
        Assert.AreEqual(expected, Filter.Scrub(text));
    }

    [TestMethod]
    [DataRow("Windows Firewall is off for the Public network.")]
    [DataRow(@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon")]
    [DataRow("malice and palaces")]
    [DataRow("")]
    public void OrdinaryText_IsLeftAlone(string text)
    {
        Assert.AreEqual(text, Filter.Scrub(text));
    }

    [TestMethod]
    [DataRow("Administrator")]
    [DataRow("user")]
    [DataRow("Admin")]
    public void AnAccountNameThatIsAnOrdinaryWord_DoesNotMangleResultText(string accountName)
    {
        var filter = new PrivacyFilter($@"C:\Users\{accountName}", accountName, "DESKTOP-EXAMPLE");

        Assert.AreEqual(
            "Reading the firewall state needs administrator rights.",
            filter.Scrub("Reading the firewall state needs administrator rights."));
        Assert.AreEqual("This check reads the user's own settings.", filter.Scrub("This check reads the user's own settings."));

        // The profile path is still hidden, and a placeholder is never replaced a second time.
        Assert.AreEqual(@"%USERPROFILE%\.npmrc", filter.Scrub($@"C:\Users\{accountName}\.npmrc"));
        Assert.AreEqual(@"C:\Users\<user>\x", filter.Scrub(@"C:\Users\someoneelse\x"));
    }

    [TestMethod]
    public void TextAfterAnUnquotedProfilePath_IsKept()
    {
        Assert.AreEqual(
            @"C:\Users\<user> could not be opened because the file is in use: sharing violation",
            Filter.Scrub(@"C:\Users\bob could not be opened because the file is in use: sharing violation"));
    }

    [TestMethod]
    public void AProfileFolderWithASpace_IsReplacedWhole_WhenAPathFollows()
    {
        Assert.AreEqual(@"C:\Users\<user>\.gitconfig", Filter.Scrub(@"C:\Users\Bob Smith\.gitconfig"));
    }

    [TestMethod]
    public void AVeryShortUserName_IsNotReplacedInsideOrdinaryWords()
    {
        var filter = new PrivacyFilter(@"C:\Users\al", "al", "PC");

        Assert.AreEqual("The firewall is on for all networks.", filter.Scrub("The firewall is on for all networks."));
        Assert.AreEqual(@"%USERPROFILE%\x", filter.Scrub(@"C:\Users\al\x"));
    }

    [TestMethod]
    public void Outcome_IsScrubbedInEveryField()
    {
        CheckOutcome outcome = CheckOutcome.Fail(
            "Token of alice found",
            Finding.Problem(@"C:\Users\alice\.npmrc", "token (alice)", "none for alice", @"C:\Users\alice\.npmrc:2"));

        CheckOutcome scrubbed = Filter.Scrub(outcome);

        Finding finding = scrubbed.Findings[0];
        string everything = string.Join("|", scrubbed.Summary, finding.Item, finding.Found, finding.Expected, finding.Source);
        Assert.IsFalse(everything.Contains("alice", StringComparison.OrdinalIgnoreCase), everything);
        Assert.AreEqual(CheckStatus.Fail, scrubbed.Status);
        Assert.AreEqual(FindingStatus.Problem, finding.Status);
    }

    [TestMethod]
    public void NoneFilter_ChangesNothing()
    {
        Assert.AreEqual(@"C:\Temp\alice on DESKTOP-EXAMPLE", PrivacyFilter.None.Scrub(@"C:\Temp\alice on DESKTOP-EXAMPLE"));
        Assert.AreEqual(@"C:\Users\alice\.npmrc", PrivacyFilter.None.Scrub(@"C:\Users\alice\.npmrc"));
    }

    [TestMethod]
    public void Wording_JoinsLists_AndAgreesInNumber()
    {
        Assert.AreEqual("C:", Wording.JoinWithAnd(["C:"]));
        Assert.AreEqual("C: and D:", Wording.JoinWithAnd(["C:", "D:"]));
        Assert.AreEqual("C:, D: and E:", Wording.JoinWithAnd(["C:", "D:", "E:"]));
        Assert.AreEqual("is", Wording.IsOrAre(1));
        Assert.AreEqual("are", Wording.IsOrAre(2));
        Assert.AreEqual(string.Empty, Wording.Plural(1));
        Assert.AreEqual("s", Wording.Plural(3));
    }
}
