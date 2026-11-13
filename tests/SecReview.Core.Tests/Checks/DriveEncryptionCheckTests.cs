using SecReview.Checks;
using SecReview.Checks.BuiltIn;
using SecReview.Probing;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.Checks;

[TestClass]
public sealed class DriveEncryptionCheckTests
{
    private static readonly DriveEncryptionCheck Check = new();

    private static FakeProbes With(params DriveEncryption[] drives) =>
        new() { DriveEncryption = ProbeResult<IReadOnlyList<DriveEncryption>>.Ok(drives) };

    private static DriveEncryption System(DriveEncryptionState state, int? raw = null) =>
        new("C:", IsSystemDrive: true, state, raw);

    private static DriveEncryption Data(string drive, DriveEncryptionState state, string? detail = null) =>
        new(drive, IsSystemDrive: false, state, RawValue: null, detail);

    [TestMethod]
    public void SystemDriveOn_Passes()
    {
        CheckOutcome outcome = Check.Run(With(System(DriveEncryptionState.On, 1)));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("BitLocker is on for C:.", outcome.Summary);
        CollectionAssert.AreEqual(new[] { "C: (Windows): On (expected On) [ok]" }, outcome.Rows());
    }

    [TestMethod]
    public void AllDrivesOn_SaysHowMany()
    {
        CheckOutcome outcome = Check.Run(With(System(DriveEncryptionState.On), Data("D:", DriveEncryptionState.On)));

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("BitLocker is on for all 2 drives.", outcome.Summary);
    }

    [TestMethod]
    public void SystemDriveOff_Fails()
    {
        CheckOutcome outcome = Check.Run(With(System(DriveEncryptionState.Off, 2)));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("BitLocker is off on C:.", outcome.Summary);
        CollectionAssert.AreEqual(new[] { "C: (Windows): Off (expected On) [problem]" }, outcome.Rows());
    }

    [TestMethod]
    public void DataDriveOff_Fails_AndNamesOnlyThatDrive()
    {
        CheckOutcome outcome = Check.Run(With(System(DriveEncryptionState.On), Data("D:", DriveEncryptionState.Off)));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("BitLocker is off on D:.", outcome.Summary);
        CollectionAssert.Contains(outcome.Rows(), "C: (Windows): On (expected On) [ok]");
        CollectionAssert.Contains(outcome.Rows(), "D:: Off (expected On) [problem]");
    }

    [TestMethod]
    [DataRow(DriveEncryptionState.Other, DisplayName = "suspended, encrypting or locked")]
    [DataRow(DriveEncryptionState.NotReported, DisplayName = "Windows reports nothing")]
    [DataRow(DriveEncryptionState.Unreadable, DisplayName = "could not be read")]
    public void AnyStateOtherThanOnOrOff_IsNeverAPass_AndAsksForTheAdministratorCheck(DriveEncryptionState state)
    {
        CheckOutcome outcome = Check.Run(With(System(state)));

        Assert.AreEqual(CheckStatus.NeedsAdmin, outcome.Status);
        StringAssert.Contains(outcome.Summary, "does not confirm that C: is fully protected");
        Assert.AreEqual(FindingStatus.Problem, outcome.Findings[0].Status);
    }

    [TestMethod]
    public void ADefiniteOff_WinsOverAnUnconfirmedDrive()
    {
        CheckOutcome outcome = Check.Run(With(
            System(DriveEncryptionState.Other), Data("D:", DriveEncryptionState.Off)));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("BitLocker is off on D:.", outcome.Summary);
    }

    [TestMethod]
    public void AnUnreadableDrive_ShowsItsReason()
    {
        CheckOutcome outcome = Check.Run(With(
            System(DriveEncryptionState.On),
            Data("E:", DriveEncryptionState.Unreadable, "The drive is locked.")));

        Assert.AreEqual(CheckStatus.NeedsAdmin, outcome.Status);
        Assert.AreEqual("The drive is locked.", outcome.Findings[1].Found);
    }

    [TestMethod]
    public void NoSystemDriveInTheAnswer_IsCouldNotCheck()
    {
        CheckOutcome outcome = Check.Run(With(Data("D:", DriveEncryptionState.On)));

        Assert.AreEqual(CheckStatus.Error, outcome.Status);
    }

    [TestMethod]
    public void DrivesCannotBeRead_IsCouldNotCheck_NeverAPass()
    {
        var probes = new FakeProbes { DriveEncryption = ProbeFailure.Failed("Reading the drives failed.") };

        Assert.AreEqual(CheckStatus.Error, Check.Run(probes).Status);
    }

    [TestMethod]
    public void TwoUnconfirmedDrives_ReadGrammatically()
    {
        CheckOutcome outcome = Check.Run(With(
            System(DriveEncryptionState.Other), Data("D:", DriveEncryptionState.Other)));

        StringAssert.Contains(outcome.Summary, "that C: and D: are fully protected");
    }

    [TestMethod]
    public void TheCheck_GainsDetailFromAnAdministratorScan()
    {
        Assert.AreEqual(AdminNeed.ForFullDetail, Check.Definition.NeedsAdmin);
    }

    // With administrator rights the documented BitLocker class is read:
    // ProtectionStatus 0 off, 1 on, 2 unknown; ConversionStatus 0 decrypted, 1 encrypted,
    // 2 encrypting, 3 decrypting, 4 encryption paused, 5 decryption paused.

    private static FakeProbes Elevated(DriveEncryptionState shellState, params (string Drive, long Protection, long Conversion)[] volumes)
    {
        FakeProbes probes = With(System(shellState));
        probes.WithWmiObjects(
            DriveEncryptionCheck.WmiNamespace,
            DriveEncryptionCheck.WmiClass,
            [.. volumes.Select(v => FakeProbes.Wmi(
                ("DriveLetter", v.Drive), ("ProtectionStatus", v.Protection), ("ConversionStatus", v.Conversion)))]);
        return probes;
    }

    [TestMethod]
    public void Elevated_ProtectionOn_Passes_EvenWhenTheNormalViewWasUnsure()
    {
        CheckOutcome outcome = Check.Run(Elevated(DriveEncryptionState.Other, ("C:", 1, 1)), elevated: true);

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("BitLocker is on for C:.", outcome.Summary);
    }

    [TestMethod]
    [DataRow(0L, "Off", "BitLocker is off on C:.")]
    [DataRow(1L, "Suspended", "BitLocker is suspended on C:.")]
    [DataRow(2L, "Still encrypting", "BitLocker is still encrypting on C:.")]
    [DataRow(3L, "Being decrypted", "BitLocker is being decrypted on C:.")]
    [DataRow(4L, "Paused while encrypting", "BitLocker is paused while encrypting on C:.")]
    [DataRow(5L, "Paused while decrypting", "BitLocker is paused while decrypting on C:.")]
    public void Elevated_ProtectionOff_Fails_AndSaysExactlyWhy(long conversion, string found, string summary)
    {
        // The normal view says "on" (or is unsure); the documented status is what counts.
        CheckOutcome outcome = Check.Run(Elevated(DriveEncryptionState.On, ("C:", 0, conversion)), elevated: true);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual(summary, outcome.Summary);
        Assert.AreEqual(found, outcome.Findings[0].Found);
    }

    [TestMethod]
    public void Elevated_SuspendedBitLocker_Fails_UnlikeAToolThatTreatsItAsProtected()
    {
        CheckOutcome outcome = Check.Run(Elevated(DriveEncryptionState.Other, ("C:", 0, 1)), elevated: true);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("Suspended", outcome.Findings[0].Found);
    }

    [TestMethod]
    public void Elevated_ProtectionUnknown_IsCouldNotCheck_NotAnotherRequestToElevate()
    {
        CheckOutcome outcome = Check.Run(Elevated(DriveEncryptionState.Other, ("C:", 2, 1)), elevated: true);

        Assert.AreEqual(CheckStatus.Error, outcome.Status);
        StringAssert.Contains(outcome.Summary, "may be locked");
        Assert.AreEqual("Locked or not determined", outcome.Findings.Single().Found, "the evidence is kept");
    }

    [TestMethod]
    public void Elevated_DetailsCannotBeRead_AndTheNormalViewIsUnsure_IsCouldNotCheck()
    {
        FakeProbes probes = With(System(DriveEncryptionState.Other));
        probes.WithWmiFailure(
            DriveEncryptionCheck.WmiNamespace, DriveEncryptionCheck.WmiClass, ProbeFailure.Failed("WMI failed."));

        CheckOutcome outcome = Check.Run(probes, elevated: true);

        Assert.AreEqual(CheckStatus.Error, outcome.Status);
        StringAssert.Contains(outcome.Summary, "could not be read");
        StringAssert.Contains(outcome.Summary, "WMI failed.", "the reason is passed on, not swallowed");
        Assert.IsFalse(outcome.Summary.Contains("locked", StringComparison.Ordinal), "a failed reading is not a locked drive");
        Assert.AreEqual(1, outcome.Findings.Count, "the evidence is kept");
    }

    [TestMethod]
    public void Elevated_DetailsCannotBeRead_IsCouldNotCheck_TheShellIsNotAskedInstead()
    {
        FakeProbes probes = With(System(DriveEncryptionState.Off, 2));
        probes.WithWmiFailure(
            DriveEncryptionCheck.WmiNamespace, DriveEncryptionCheck.WmiClass, ProbeFailure.Failed("WMI failed."));

        CheckOutcome outcome = Check.Run(probes, elevated: true);

        Assert.AreEqual(CheckStatus.Error, outcome.Status);
        StringAssert.Contains(outcome.Summary, "WMI failed.");
        Assert.AreEqual("Could not be read", outcome.Findings.Single().Found);
        Assert.AreEqual(0, probes.ShellDriveReads);
    }

    [TestMethod]
    public void Elevated_NeverAsksTheShell()
    {
        // With administrator rights the shell (which other software can extend) is not loaded.
        FakeProbes probes = Elevated(DriveEncryptionState.Other, ("C:", 1, 1));

        Assert.AreEqual(CheckStatus.Pass, Check.Run(probes, elevated: true).Status);
        Assert.AreEqual(0, probes.ShellDriveReads);
    }

    [TestMethod]
    public void Elevated_TheDrivesComeFromTheDriveList_NotFromTheShell()
    {
        // The shell's answer could not even be read; the elevated check does not need it.
        var probes = new FakeProbes
        {
            DriveEncryption = ProbeFailure.Failed("The shell failed."),
            FixedDrives = ProbeResult<IReadOnlyList<FixedDrive>>.Ok([new("C:", IsSystemDrive: true), new("D:", IsSystemDrive: false)]),
        };
        probes.WithWmiObjects(
            DriveEncryptionCheck.WmiNamespace,
            DriveEncryptionCheck.WmiClass,
            FakeProbes.Wmi(("DriveLetter", "C:"), ("ProtectionStatus", 1L), ("ConversionStatus", 1L)),
            FakeProbes.Wmi(("DriveLetter", "D:"), ("ProtectionStatus", 1L), ("ConversionStatus", 1L)));

        CheckOutcome outcome = Check.Run(probes, elevated: true);

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("BitLocker is on for all 2 drives.", outcome.Summary);
    }

    [TestMethod]
    public void Elevated_ADriveBitLockerDoesNotList_IsCouldNotCheck_NeverAPass()
    {
        FakeProbes probes = With(System(DriveEncryptionState.On), Data("D:", DriveEncryptionState.On));
        probes.WithWmiObjects(
            DriveEncryptionCheck.WmiNamespace,
            DriveEncryptionCheck.WmiClass,
            FakeProbes.Wmi(("DriveLetter", "C:"), ("ProtectionStatus", 1L), ("ConversionStatus", 1L)));

        CheckOutcome outcome = Check.Run(probes, elevated: true);

        Assert.AreEqual(CheckStatus.Error, outcome.Status);
        StringAssert.Contains(outcome.Summary, "D:");
        Assert.AreEqual("Not reported by Windows", outcome.Findings[1].Found);
    }

    [TestMethod]
    public void Elevated_DrivesCannotBeListed_IsCouldNotCheck()
    {
        var probes = new FakeProbes { FixedDrives = ProbeFailure.Failed("Listing failed.") };

        Assert.AreEqual(CheckStatus.Error, Check.Run(probes, elevated: true).Status);
    }

    [TestMethod]
    public void NotElevated_NeverReadsTheAdministratorDetails()
    {
        // No WMI answer is set up: a read would fail the fake loudly. The check must not try.
        FakeProbes probes = With(System(DriveEncryptionState.On, 1));
        CheckOutcome outcome = Check.Run(probes, elevated: false);

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.IsTrue(probes.ShellDriveReads > 0, "a normal user's check reads the shell");
    }

    [TestMethod]
    public void Elevated_SeveralDrivesInDifferentStates_NamesThem()
    {
        FakeProbes probes = With(System(DriveEncryptionState.On), Data("D:", DriveEncryptionState.Other));
        probes.WithWmiObjects(
            DriveEncryptionCheck.WmiNamespace,
            DriveEncryptionCheck.WmiClass,
            FakeProbes.Wmi(("DriveLetter", "C:"), ("ProtectionStatus", 0L), ("ConversionStatus", 1L)),
            FakeProbes.Wmi(("DriveLetter", "D:"), ("ProtectionStatus", 0L), ("ConversionStatus", 0L)),
            FakeProbes.Wmi(("DriveLetter", null), ("ProtectionStatus", 0L), ("ConversionStatus", 0L)));

        CheckOutcome outcome = Check.Run(probes, elevated: true);

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("BitLocker is not protecting C: and D:.", outcome.Summary);
        Assert.AreEqual(2, outcome.Findings.Count);
    }
}
