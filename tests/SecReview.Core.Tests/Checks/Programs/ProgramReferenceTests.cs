using SecReview.Checks.BuiltIn.Programs;
using SecReview.Probing;
using SecReview.SupplyChain;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.Checks.Programs;

[TestClass]
public sealed class ProgramReferenceTests
{
    private const string Secret = "made-up-secret-argument";

    private static readonly MachineContext Machine = Load(new FakeProbes()
        .WithRegistryValue(
            RegistryRoot.LocalMachine, PersistentEnvironment.MachineKey, "Path", RegistryValue.FromText(@"%SystemRoot%\system32;%SystemRoot%;;""C:\Tools\bin"";relative\folder"))
        .WithRegistryValue(RegistryRoot.LocalMachine, PersistentEnvironment.MachineKey, "EXAMPLE_HOME", RegistryValue.FromText(@"%ProgramFiles%\Example"))
        .WithRegistryValue(RegistryRoot.LocalMachine, PersistentEnvironment.MachineKey, "TEMP", RegistryValue.FromText(@"%SystemRoot%\TEMP")));

    private static MachineContext Load(FakeProbes probes)
    {
        Assert.IsNull(MachineContext.Load(probes.Build(), out MachineContext machine));
        return machine;
    }

    private static ProgramReference Parse(string? text, CommandForm form = CommandForm.CommandLine, bool view32 = false) =>
        ProgramReference.Parse(text, form, Machine, view32);

    private static void AssertFiles(ProgramReference reference, params string[] expected)
    {
        Assert.AreEqual(ReferenceKind.Local, reference.Kind, reference.Problem);
        CollectionAssert.AreEqual(expected, reference.Candidates.ToArray());
    }

    [TestMethod]
    public void AQuotedProgram_IsThatFileAlone_WhateverFollows()
    {
        ProgramReference reference = Parse(@"""C:\Program Files\Example\agent.exe"" --run " + Secret);

        AssertFiles(reference, @"C:\Program Files\Example\agent.exe");
        Assert.IsTrue(reference.Quoted);
        Assert.IsFalse(reference.Ambiguous);
    }

    [TestMethod]
    public void AnUnquotedPathWithSpaces_IsEveryFileWindowsWouldTry_InItsOrder()
    {
        ProgramReference reference = Parse(@"C:\Program Files\Example Tools\agent.exe --run " + Secret);

        AssertFiles(reference, @"C:\Program.exe", @"C:\Program Files\Example.exe", @"C:\Program Files\Example Tools\agent.exe");
        Assert.IsTrue(reference.Ambiguous);
        Assert.AreEqual(@"C:\Program Files\Example Tools\agent.exe", reference.Intended);
    }

    [TestMethod]
    public void AnUnquotedPathWithoutSpaces_IsOneFile()
    {
        ProgramReference reference = Parse(@"C:\Tools\Example\agent.exe -x " + Secret);

        AssertFiles(reference, @"C:\Tools\Example\agent.exe");
        Assert.IsFalse(reference.Ambiguous);
    }

    [TestMethod]
    public void AProgramWithoutAnEnding_GetsExe_AndItsArgumentsStayOut()
    {
        ProgramReference plain = Parse(@"C:\Tools\Example\agent run " + Secret);
        ProgramReference switched = Parse(@"C:\Program Files\Example\agent --token " + Secret);
        ProgramReference otherPath = Parse(@"C:\Tools\agent --config C:\Tools\" + Secret + @"\file.txt");

        AssertFiles(plain, @"C:\Tools\Example\agent.exe");
        AssertFiles(switched, @"C:\Program.exe", @"C:\Program Files\Example\agent.exe");
        AssertFiles(otherPath, @"C:\Tools\agent.exe");
        Assert.IsFalse(plain.Complete);
        Assert.AreEqual(@"C:\Program.exe", switched.Intended, "where the name ends is a guess: only the first is shown");
    }

    [TestMethod]
    public void AFileNameWithASpace_IsStillFound_WhenItEndsLikeAProgram()
    {
        AssertFiles(Parse(@"C:\Tools\Example\my agent.exe -x"), @"C:\Tools\Example\my.exe", @"C:\Tools\Example\my agent.exe");
    }

    [TestMethod]
    [DataRow(@"%SystemRoot%\System32\svchost.exe -k netsvcs -p", @"C:\Windows\System32\svchost.exe")]
    [DataRow(@"\SystemRoot\System32\drivers\example.sys", @"C:\Windows\System32\drivers\example.sys")]
    [DataRow(@"System32\drivers\example.sys", @"C:\Windows\System32\drivers\example.sys")]
    [DataRow(@"\??\C:\Tools\Example\driver.sys", @"C:\Tools\Example\driver.sys")]
    [DataRow(@"""\??\C:\Tools\Example Driver\driver.sys""", @"C:\Tools\Example Driver\driver.sys")]
    [DataRow(@"%windir%\example.exe", @"C:\Windows\example.exe")]
    [DataRow(@"%EXAMPLE_HOME%\agent.exe", @"C:\Program.exe|C:\Program Files\Example\agent.exe")]
    [DataRow(@"""%ProgramData%\Example\agent.exe"" --run", @"C:\ProgramData\Example\agent.exe")]
    public void AServicesProgram_IsReadTheWaysWindowsWritesIt(string image, string expected)
    {
        AssertFiles(Parse(image, CommandForm.ServiceImage), expected.Split('|'));
    }

    [TestMethod]
    public void APathFromTheWindowsFolder_IsOnlyThat_ForAService()
    {
        Assert.AreEqual(ReferenceKind.Unresolvable, Parse(@"System32\drivers\example.sys").Kind);
        Assert.AreEqual(ReferenceKind.Unresolvable, Parse(@"agent\run.exe", CommandForm.ServiceImage).Kind);
        Assert.AreEqual(ReferenceKind.Unresolvable, Parse(@"C:agent.exe").Kind);
        Assert.AreEqual(ReferenceKind.Unresolvable, Parse(@"\\.\C:\Tools\agent.exe").Kind);
    }

    [TestMethod]
    public void AProgramNamedWithoutAFolder_IsLookedForWhereWindowsLooks()
    {
        ProgramReference reference = Parse("notepad " + Secret);

        AssertFiles(reference, @"C:\Windows\System32\notepad.exe", @"C:\Windows\notepad.exe", @"C:\Tools\bin\notepad.exe");
        Assert.IsTrue(reference.ByName);
        Assert.IsFalse(reference.Ambiguous);
        Assert.AreEqual(@"C:\Windows\System32\notepad.exe", reference.Intended);
    }

    [TestMethod]
    [DataRow(@"\\server\share\agent.exe /x")]
    [DataRow(@"""\\server\share\an agent.exe"" /x")]
    [DataRow(@"\\?\UNC\server\share\agent.exe")]
    [DataRow(@"//server/share/agent.exe")]
    public void ANetworkPath_IsOnlySaidToBeOne_AndItsNameIsNotKept(string command)
    {
        ProgramReference reference = Parse(command);

        Assert.AreEqual(ReferenceKind.Network, reference.Kind);
        Assert.AreEqual(0, reference.Candidates.Count);
    }

    [TestMethod]
    [DataRow(@"%APPDATA%\Example\agent.exe", false)]
    [DataRow(@"""%LOCALAPPDATA%\Example App\agent.exe"" -x", true)]
    [DataRow(@"%LOCALAPPDATA%\Example App\agent.exe -x", false)]
    [DataRow(@"%TEMP%\agent.exe", false)]
    public void APathThatDiffersPerUser_IsNotResolved_AndSaysSo(string command, bool quoted)
    {
        ProgramReference reference = Parse(command);

        Assert.AreEqual(ReferenceKind.Unresolvable, reference.Kind);
        Assert.IsTrue(reference.PerUser, "a variable of that name set for the PC does not make it the same for everyone");
        Assert.AreEqual(quoted, reference.Quoted);
    }

    [TestMethod]
    public void AVariableNotSetForThePc_IsNotGuessed()
    {
        ProgramReference reference = Parse(@"%NOT_SET_ANYWHERE%\agent.exe");

        Assert.AreEqual(ReferenceKind.Unresolvable, reference.Kind);
        Assert.IsFalse(reference.PerUser);
        StringAssert.Contains(reference.Problem, "variable");
    }

    [TestMethod]
    public void AnArgumentThatLooksLikeAVariable_IsLeftAlone()
    {
        AssertFiles(Parse(@"""C:\Tools\Example\agent.exe"" ""%1"" %*"), @"C:\Tools\Example\agent.exe");
        AssertFiles(Parse(@"C:\Tools\Example\agent.exe %NOT_SET_ANYWHERE%"), @"C:\Tools\Example\agent.exe");
    }

    [TestMethod]
    [DataRow(null)]
    [DataRow("")]
    [DataRow("   ")]
    [DataRow("\"\"")]
    public void NothingStored_IsEmpty(string? command)
    {
        Assert.AreEqual(ReferenceKind.Empty, Parse(command).Kind);
    }

    [TestMethod]
    public void TextThatIsNotACommand_IsNotRead()
    {
        Assert.AreEqual(ReferenceKind.Unresolvable, Parse("C:\\Tools\\a.exe\r\nC:\\Tools\\b.exe").Kind);
        Assert.AreEqual(ReferenceKind.Unresolvable, Parse(@"C:\Tools\" + new string('a', 5000) + ".exe").Kind);
        Assert.AreEqual(ReferenceKind.Unresolvable, Parse(@"""C:\Tools\Example\agent.exe").Kind);
        Assert.AreEqual(ReferenceKind.Unresolvable, Parse(@"C:\Tools\Example\").Kind);
    }

    [TestMethod]
    public void APlainPath_IsTakenWhole_SpacesAndAll()
    {
        AssertFiles(Parse(@"C:\Program Files\Example Tools\agent.exe", CommandForm.PathOnly), @"C:\Program Files\Example Tools\agent.exe");
        AssertFiles(Parse(@"C:\Program Files\Example Tools\agent", CommandForm.PathOnly), @"C:\Program Files\Example Tools\agent");
        AssertFiles(Parse(@"""C:\Program Files\Example Tools\lib.dll""", CommandForm.PathOnly), @"C:\Program Files\Example Tools\lib.dll");
        AssertFiles(Parse("example.dll", CommandForm.PathOnly), @"C:\Windows\System32\example.dll", @"C:\Windows\example.dll", @"C:\Tools\bin\example.dll");
    }

    [TestMethod]
    public void APlainPathThatHasArgumentsAfterAll_LosesThem_AndIsNotTakenForAScriptHostsCommand()
    {
        ProgramReference withArguments = Parse(@"C:\Program Files\Example Tools\agent.exe -quiet " + Secret, CommandForm.PathOnly);
        ProgramReference host = Parse(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", CommandForm.PathOnly);

        AssertFiles(withArguments, @"C:\Program Files\Example Tools\agent.exe");
        Assert.IsFalse(host.CommandOnly, "nothing was given for it to run");
        Assert.IsNull(host.Target);
    }

    [TestMethod]
    public void ForA32BitProgram_TheFoldersAreThe32BitOnes()
    {
        AssertFiles(Parse(@"%ProgramFiles%\Example\agent.exe", CommandForm.PathOnly, view32: true), @"C:\Program Files (x86)\Example\agent.exe");
        AssertFiles(Parse(@"C:\Windows\System32\example.dll", CommandForm.PathOnly, view32: true), @"C:\Windows\SysWOW64\example.dll");
        AssertFiles(
            Parse("example.dll", CommandForm.PathOnly, view32: true),
            @"C:\Windows\SysWOW64\example.dll", @"C:\Windows\example.dll", @"C:\Windows\system32\example.dll", @"C:\Tools\bin\example.dll");
    }

    [TestMethod]
    [DataRow(@"rundll32.exe C:\Tools\Example\lib.dll,Start now", @"C:\Tools\Example\lib.dll")]
    [DataRow(@"C:\Windows\System32\rundll32.exe ""C:\Tools\Example Lib\lib.dll"",Start", @"C:\Tools\Example Lib\lib.dll")]
    [DataRow(@"""C:\Windows\SysWOW64\rundll32.exe"" C:\Tools\Example\lib.dll,Start", @"C:\Tools\Example\lib.dll")]
    [DataRow(@"regsvr32 /s ""C:\Tools\Example\lib.dll""", @"C:\Tools\Example\lib.dll")]
    [DataRow(@"cmd.exe /c ""C:\Tools\Example\run.bat"" --quiet", @"C:\Tools\Example\run.bat")]
    [DataRow(@"cmd /C """"C:\Tools\Example App\run.bat"" --quiet""", @"C:\Tools\Example App\run.bat")]
    [DataRow(@"%SystemRoot%\System32\cmd.exe /c C:\Tools\Example\run.cmd", @"C:\Tools\Example\run.cmd")]
    [DataRow(@"powershell.exe -NoProfile -ExecutionPolicy Bypass -File ""C:\Tools\Example\run.ps1"" -x", @"C:\Tools\Example\run.ps1")]
    [DataRow(@"wscript.exe //B //Nologo C:\Tools\Example\run.vbs", @"C:\Tools\Example\run.vbs")]
    [DataRow(@"msiexec /i ""C:\Tools\Example\setup.msi"" /qn", @"C:\Tools\Example\setup.msi")]
    public void AWindowsProgramThatRunsWhatItIsGiven_AlsoNamesThat(string command, string target)
    {
        ProgramReference reference = Parse(command + " " + Secret);

        Assert.AreEqual(ReferenceKind.Local, reference.Kind);
        Assert.IsNotNull(reference.Target, "the thing it runs");
        AssertFiles(reference.Target, target);
        Assert.IsFalse(reference.CommandOnly);
        StringAssert.StartsWith(reference.Candidates[0], @"C:\Windows\");
    }

    [TestMethod]
    public void ALibraryNamedWithoutAFolder_IsLookedUpToo()
    {
        ProgramReference reference = Parse("rundll32 shell32.dll,Control_RunDLL");

        Assert.IsTrue(reference.Target!.ByName);
        Assert.AreEqual(@"C:\Windows\System32\shell32.dll", reference.Target.Candidates[0]);
    }

    [TestMethod]
    [DataRow(@"cmd /c echo made up > C:\Tools\out.txt & del C:\Tools\other.txt")]
    [DataRow(@"cmd /c start """" C:\Tools\Example\agent.exe")]
    [DataRow(@"cmd.exe")]
    [DataRow(@"C:\Windows\System32\cmd.exe /q /c del /q ""C:\Tools\Example\old.tmp""")]
    [DataRow(@"cmd /c rmdir /s /q C:\Tools\Example\old")]
    [DataRow(@"powershell -Command ""Get-Date""")]
    [DataRow(@"powershell.exe -EncodedCommand AAAA")]
    [DataRow(@"rundll32.exe")]
    [DataRow(@"wscript.exe //B relative\run.vbs")]
    [DataRow(@"msiexec /x {11111111-2222-3333-4444-555555555555}")]
    public void WhatSuchAProgramRuns_WhenItCannotBeTold_IsSaidNotToBeJudged(string command)
    {
        ProgramReference reference = Parse(command);

        Assert.AreEqual(ReferenceKind.Local, reference.Kind);
        Assert.IsNull(reference.Target);
        Assert.IsTrue(reference.CommandOnly);
    }

    [TestMethod]
    public void AnInstalledProduct_OrAProgramOfTheSameNameElsewhere_HasNothingMoreToJudge()
    {
        ProgramReference product = Parse("msiexec /i {11111111-2222-3333-4444-555555555555} /qn");
        ProgramReference elsewhere = Parse(@"C:\Tools\cmd.exe /c C:\Tools\Example\run.bat");

        Assert.IsNull(product.Target);
        Assert.IsFalse(product.CommandOnly);
        Assert.IsNull(elsewhere.Target, "only the Windows program of that name is known to run its argument");
        Assert.IsFalse(elsewhere.CommandOnly);
    }

    [TestMethod]
    public void ThePcsSearchPath_IsReadAsWritten_WithoutEmptyEntriesOrQuotes()
    {
        CollectionAssert.AreEqual(
            new[] { @"%SystemRoot%\system32", "%SystemRoot%", @"C:\Tools\bin", @"relative\folder" },
            Machine.PathEntries.ToArray());
    }

    [TestMethod]
    public void TheFoldersOrVariables_NotBeingReadable_IsAnOutcome_NotAGuess()
    {
        var denied = new FakeProbes { RegistryFailure = ProbeFailure.AccessDenied() };

        Assert.IsNotNull(MachineContext.Load(denied.Build(), out _));
    }

    [TestMethod]
    public void AnyText_IsReadWithoutFailing_AndNeverKeepsAnArgument()
    {
        string[] pieces =
        [
            @"C:\", @"C:\Program Files\", "Example", " ", "  ", "\"", "agent.exe", "agent", ".dll", ",", "%SystemRoot%", "%APPDATA%", "%", @"\\server\share\",
            "cmd", " /c ", "rundll32 ", "powershell ", "-File ", "msiexec /i ", "/", "-", @"\", ":", "&", "\t", @"\??\", @"System32\", "..", "{", "wscript //B ",
        ];
        var random = new Random(20261112);
        foreach (CommandForm form in Enum.GetValues<CommandForm>())
        {
            for (int round = 0; round < 3000; round++)
            {
                string program = string.Concat(Enumerable.Range(0, random.Next(1, 8)).Select(_ => pieces[random.Next(pieces.Length)]));
                string text = program + " --token " + Secret;

                ProgramReference reference = ProgramReference.Parse(text, form, Machine, view32: random.Next(2) == 0);

                Assert.IsTrue(reference.Candidates.Count <= ProgramReference.MaximumCandidates, text);
                if (form == CommandForm.PathOnly && !text.StartsWith('"'))
                {
                    // A plain path has no arguments: all of it is the path.
                    continue;
                }

                Assert.IsFalse(reference.Intended.Contains(Secret, StringComparison.Ordinal), text);
                Assert.IsTrue(!reference.Complete || reference.Candidates.All(c => !c.Contains(Secret, StringComparison.Ordinal)), text);
                Assert.IsFalse(reference.Target?.Intended.Contains(Secret, StringComparison.Ordinal) ?? false, text);
            }
        }
    }
}
