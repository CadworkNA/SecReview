using SecReview.Checks;
using SecReview.Checks.BuiltIn.Programs;
using SecReview.Probing;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.Checks.Programs;

/// <summary>A made-up PC for the checks that judge who can change a program.</summary>
internal static class ProgramChecksFixture
{
    /// <summary>A program installed the usual way: only administrators can change it.</summary>
    public const string Installed = @"C:\Program Files\Example\agent.exe";

    /// <summary>A program in a folder made at the top of the drive, which standard users can change.</summary>
    public const string Loose = @"C:\Tools\Example\agent.exe";

    /// <summary>An argument no result may ever show.</summary>
    public const string Secret = "made-up-secret-argument";

    private const string Winlogon = StartupProgramsCheck.WinlogonKey;

    /// <summary>
    /// Windows as it sets itself up, both programs above, and a registry only administrators
    /// can change.
    /// </summary>
    public static FakeProbes Pc() => new FakeProbes()
        .WithStandardWindows()
        .WithKeyAccessBelow(RegistryRoot.LocalMachine, "SOFTWARE", FakeAccess.Protected)
        .WithKeyAccessBelow(RegistryRoot.LocalMachine, "SYSTEM", FakeAccess.Protected)
        .WithFile(@"C:\Windows\explorer.exe", "made up")
        .WithFile(@"C:\Windows\System32\userinit.exe", "made up")
        .WithFile(@"C:\Windows\System32\svchost.exe", "made up")
        .WithFile(@"C:\Windows\System32\rundll32.exe", "made up")
        .WithFile(@"C:\Windows\System32\cmd.exe", "made up")
        .WithFile(Installed, "made up")
        .WithFile(Loose, "made up")
        .WithAccessBelow(@"C:\Tools", FakeAccess.Protected.Allow(FakeAccess.AuthenticatedUsers, FakeAccess.Level.Modify))
        .WithRegistryValue(RegistryRoot.LocalMachine, Winlogon, "Shell", RegistryValue.FromText("explorer.exe"))
        .WithRegistryValue(RegistryRoot.LocalMachine, Winlogon, "Userinit", RegistryValue.FromText(@"C:\Windows\system32\userinit.exe,"));

    public static FakeProbes WithText(this FakeProbes probes, string key, string name, string text) =>
        probes.WithRegistryValue(RegistryRoot.LocalMachine, key, name, RegistryValue.FromText(text));

    /// <summary>A service or driver as its settings are stored: 0x10 is a program of its own, 2 starts with Windows.</summary>
    public static FakeProbes Service(
        this FakeProbes probes, string name, string image, long type = 0x10, long start = 2, string? library = null)
    {
        string key = $@"{ServiceProgramsCheck.ServicesKey}\{name}";
        probes
            .WithRegistryNumber(RegistryRoot.LocalMachine, key, "Type", type)
            .WithRegistryNumber(RegistryRoot.LocalMachine, key, "Start", start)
            .WithText(key, "ImagePath", image);
        return library is null ? probes : probes.WithText(key + @"\Parameters", "ServiceDll", library);
    }

    /// <summary>A component loaded into the program that asks for it.</summary>
    public static FakeProbes InProcess(this FakeProbes probes, string id, string library, bool view32 = false) => probes.WithText(
        $@"{(view32 ? RegisteredComponentsCheck.Classes32Key : RegisteredComponentsCheck.ClassesKey)}\{id}\InprocServer32", string.Empty, library);

    /// <summary>A component started as a program of its own.</summary>
    public static FakeProbes OwnProcess(this FakeProbes probes, string id, string command) =>
        probes.WithText($@"{RegisteredComponentsCheck.ClassesKey}\{id}\LocalServer32", string.Empty, command);

    /// <summary>A program found by its short name.</summary>
    public static FakeProbes AppPath(this FakeProbes probes, string name, string program) =>
        probes.WithText($@"{RegisteredComponentsCheck.AppPathsKey}\{name}", string.Empty, program);

    /// <summary>Everything a result shows, to assert that something is not in it.</summary>
    public static string Everything(this CheckOutcome outcome) =>
        outcome.Summary + "\n" + string.Join('\n', outcome.Findings.Select(f => $"{f.Item}|{f.Found}|{f.Expected}|{f.Source}"));
}
