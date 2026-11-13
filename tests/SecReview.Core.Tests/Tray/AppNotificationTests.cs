using System.Text.RegularExpressions;
using System.Xml.Linq;
using SecReview.CommandLine;
using SecReview.Tray;

namespace SecReview.Tests.Tray;

[TestClass]
public sealed partial class AppNotificationTests
{
    [TestMethod]
    public void TheNotification_HoldsTitleReasonAndAShowButton_ThatOpenTheCheck()
    {
        XElement toast = XElement.Parse(AppNotification.Xml(new TrayNotification("Firewall is off", "Windows Firewall is off for the Public network.", "firewall.enabled")));

        Assert.AreEqual("toast", toast.Name.LocalName);
        Assert.AreEqual("show:firewall.enabled", (string?)toast.Attribute("launch"));
        Assert.AreEqual("foreground", (string?)toast.Attribute("activationType"));
        CollectionAssert.AreEqual(
            new[] { "Firewall is off", "Windows Firewall is off for the Public network." },
            toast.Descendants("text").Select(text => text.Value).ToArray());

        XElement action = toast.Descendants("action").Single();
        Assert.AreEqual("Show", (string?)action.Attribute("content"));
        Assert.AreEqual("show:firewall.enabled", (string?)action.Attribute("arguments"));
        Assert.AreEqual("foreground", (string?)action.Attribute("activationType"));
    }

    [TestMethod]
    public void SeveralChecks_OpenTheWindowAsItIs()
    {
        XElement toast = XElement.Parse(AppNotification.Xml(new TrayNotification("3 checks started failing", "a; b; c", CheckId: null)));

        Assert.AreEqual("show", (string?)toast.Attribute("launch"));
        Assert.AreEqual("show", (string?)toast.Descendants("action").Single().Attribute("arguments"));
    }

    [TestMethod]
    [DataRow("a b")]
    [DataRow("-starts-with-a-dash")]
    [DataRow("C:/made/up")]
    [DataRow("")]
    public void ACheckThatIsNotAnIdentifier_IsNotPutIntoTheArguments(string checkId)
    {
        XElement toast = XElement.Parse(AppNotification.Xml(new TrayNotification("t", "r", checkId)));

        Assert.AreEqual("show", (string?)toast.Attribute("launch"));
    }

    [TestMethod]
    public void TextThatLooksLikeMarkup_StaysText_AndWhatXmlCannotHoldIsLeftOut()
    {
        const string Title = "<b>\"x\" & 'y'</b>";
        string reason = "a\u0001b\uFFFEc\uD800d \uD83D\uDD12 \u00E9";

        XElement toast = XElement.Parse(AppNotification.Xml(new TrayNotification(Title, reason, "a.b")));

        string[] texts = [.. toast.Descendants("text").Select(text => text.Value)];
        Assert.AreEqual(Title, texts[0]);
        Assert.AreEqual("abcd \uD83D\uDD12 \u00E9", texts[1], "control characters, non-characters and a lone surrogate go; the rest stays");
        Assert.AreEqual(2, texts.Length);
        Assert.AreEqual(0, toast.Descendants("b").Count());
    }

    [TestMethod]
    [DataRow("show", null)]
    [DataRow("show:firewall.enabled", "firewall.enabled")]
    [DataRow("show:supply_chain.npm-cooldown", "supply_chain.npm-cooldown")]
    public void WhatTheNotificationHolds_IsTakenBack(string arguments, string? checkId)
    {
        Assert.IsTrue(AppNotification.TryReadArguments(arguments, out string? read));
        Assert.AreEqual(checkId, read);
    }

    [TestMethod]
    [DataRow(null)]
    [DataRow("")]
    [DataRow("Show")]
    [DataRow("show:")]
    [DataRow("show: firewall.enabled")]
    [DataRow("show:firewall.enabled ")]
    [DataRow("show:-x")]
    [DataRow("show:--demo")]
    [DataRow("show:a b")]
    [DataRow("show:C:\\made\\up")]
    [DataRow("show:..\\..\\x")]
    [DataRow("show:a/b")]
    [DataRow("show:a\nb")]
    [DataRow("show:a:b")]
    [DataRow("open:firewall.enabled")]
    [DataRow("firewall.enabled")]
    [DataRow("--show firewall.enabled")]
    [DataRow("show\0:a")]
    [DataRow("action=show&check=a")]
    public void AnythingElse_IsRefused_AndOpensNothing(string? arguments)
    {
        Assert.IsFalse(AppNotification.TryReadArguments(arguments, out string? checkId));
        Assert.IsNull(checkId);
    }

    [TestMethod]
    public void AnOverlongClick_IsRefused()
    {
        Assert.IsFalse(AppNotification.TryReadArguments("show:" + new string('a', 300), out _));
        Assert.IsFalse(AppNotification.TryReadArguments("show:" + new string('a', 101), out _), "longer than any identifier");
        Assert.IsTrue(AppNotification.TryReadArguments("show:" + new string('a', 100), out _));
    }

    [TestMethod]
    [DataRow(@"C:\Program Files\SecReview", true)]
    [DataRow(@"C:\Program Files\SecReview\", true)]
    [DataRow(@"c:\program files\secreview\", true)]
    [DataRow(@"C:\Program Files\SecReview\sub\", false)]
    [DataRow(@"C:\Program Files\SecReviewOther\", false)]
    [DataRow(@"C:\Program Files\", false)]
    [DataRow(@"C:\Program Files (x86)\SecReview\", false)]
    [DataRow(@"C:\Users\made-up\Downloads\SecReview\", false)]
    [DataRow(@"C:\Program Files\SecReview\..\Other\", false)]
    public void OnlyTheCopySetupInstalled_UsesAppNotifications(string appDirectory, bool installed)
    {
        Assert.AreEqual(installed, AppNotification.IsInstalledCopy(appDirectory, @"C:\Program Files"));
    }

    [TestMethod]
    public void WithoutAProgramFilesFolder_NoCopyIsTheInstalledOne()
    {
        Assert.IsFalse(AppNotification.IsInstalledCopy(@"C:\Program Files\SecReview\", null));
        Assert.IsFalse(AppNotification.IsInstalledCopy(@"C:\Program Files\SecReview\", " "));
        Assert.IsFalse(AppNotification.IsInstalledCopy(@"\SecReview\", "\0"));
    }

    [TestMethod]
    public void Setup_RegistersTheSameIdentityClassAndSwitch_AsTheCodeUses()
    {
        string script = Setup();

        Assert.AreEqual(AppNotification.AppId, Define(script, "AppUserModelId"));
        Assert.AreEqual(AppNotification.ActivatorId, Guid.Parse(Define(script, "ToastActivator")));
        Assert.AreEqual(AppArguments.NotificationClickSwitch, Define(script, "NotificationClickSwitch"));
        Assert.AreEqual("SecReview", AppNotification.InstallFolderName);

        // The shortcut carries both; the class starts the installed program with the switch.
        string shortcut = script.Split('\n').Single(line => line.StartsWith("Name: \"{autoprograms}", StringComparison.Ordinal));
        StringAssert.Contains(shortcut, "AppUserModelID: \"{#AppUserModelId}\"");
        StringAssert.Contains(shortcut, "AppUserModelToastActivatorCLSID: \"{#ToastActivator}\"");
        StringAssert.Contains(script, "Subkey: \"Software\\Classes\\CLSID\\{{{#ToastActivator}}\\LocalServer32\"; ValueType: string; ValueName: \"\"; ValueData: \"\"\"{app}\\{#AppExe}\"\" {#NotificationClickSwitch}\"");
        StringAssert.Contains(script, "DefaultDirName={autopf}\\{#AppName}");
    }

    private static string Setup()
    {
        using Stream stream = typeof(AppNotificationTests).Assembly.GetManifestResourceStream("SecReview.iss")
            ?? throw new AssertFailedException("installer/SecReview.iss is not embedded in the tests.");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd().Replace("\r\n", "\n", StringComparison.Ordinal);
    }

    private static string Define(string script, string name)
    {
        Match match = DefineLine().Matches(script).SingleOrDefault(found => found.Groups["name"].Value == name)
            ?? throw new AssertFailedException($"installer/SecReview.iss defines no {name}.");
        return match.Groups["value"].Value;
    }

    [GeneratedRegex("""^#define (?<name>\w+) "(?<value>[^"]*)"$""", RegexOptions.Multiline)]
    private static partial Regex DefineLine();
}
