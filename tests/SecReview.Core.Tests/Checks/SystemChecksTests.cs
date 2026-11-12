using SecReview.Checks;
using SecReview.Checks.BuiltIn;
using SecReview.Probing;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.Checks;

[TestClass]
public sealed class SystemChecksTests
{
    private static ProbeResult<CodeIntegrityState> Integrity(bool testSigning = false, bool debugging = false, bool memoryIntegrity = true) =>
        ProbeResult<CodeIntegrityState>.Ok(new CodeIntegrityState(testSigning, debugging, memoryIntegrity));

    // User Account Control

    [TestMethod]
    [DataRow(1L, CheckStatus.Pass)]
    [DataRow(0L, CheckStatus.Fail)]
    public void Uac_FollowsTheSetting(long value, CheckStatus expected)
    {
        FakeProbes probes = new FakeProbes().WithRegistryNumber(RegistryRoot.LocalMachine, UacCheck.Key, UacCheck.Value, value);

        Assert.AreEqual(expected, new UacCheck().Run(probes).Status);
    }

    [TestMethod]
    public void Uac_NotSet_IsTheWindowsDefault_On()
    {
        CheckOutcome outcome = new UacCheck().Run(new FakeProbes());

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual("On (Windows default)", outcome.Findings[0].Found);
    }

    [TestMethod]
    public void Uac_AValueOfAnUnexpectedKind_IsCouldNotCheck_NotTheDefault()
    {
        FakeProbes text = new FakeProbes().WithRegistryValue(RegistryRoot.LocalMachine, UacCheck.Key, UacCheck.Value, RegistryValue.FromText("off"));
        FakeProbes binary = new FakeProbes().WithRegistryValue(RegistryRoot.LocalMachine, UacCheck.Key, UacCheck.Value, RegistryValue.FromBinary([0]));

        Assert.AreEqual(CheckStatus.Error, new UacCheck().Run(text).Status);
        Assert.AreEqual(CheckStatus.Error, new UacCheck().Run(binary).Status);
        StringAssert.Contains(new UacCheck().Run(binary).Summary, "EnableLUA is not a number");
    }

    [TestMethod]
    public void Defender_IsPartOfTheAdministratorScan_WhichCanReadWhatANormalUserMayNot()
    {
        Assert.AreEqual(AdminNeed.ForFullDetail, new DefenderCheck().Definition.NeedsAdmin);
    }

    [TestMethod]
    public void Uac_Unreadable_IsNeverAPass()
    {
        var denied = new FakeProbes { RegistryFailure = ProbeFailure.AccessDenied() };
        var failed = new FakeProbes { RegistryFailure = ProbeFailure.Failed("Reading the registry failed.") };

        Assert.AreEqual(CheckStatus.NeedsAdmin, new UacCheck().Run(denied).Status);
        Assert.AreEqual(CheckStatus.Error, new UacCheck().Run(failed).Status);
    }

    // Secure Boot

    private static FakeProbes SecureBoot(FirmwareKind firmware, long? enabled)
    {
        var probes = new FakeProbes { Firmware = ProbeResult<FirmwareKind>.Ok(firmware) };
        return enabled is null
            ? probes
            : probes.WithRegistryNumber(RegistryRoot.LocalMachine, SecureBootCheck.Key, SecureBootCheck.Value, enabled.Value);
    }

    [TestMethod]
    public void SecureBoot_On_Passes()
    {
        Assert.AreEqual(CheckStatus.Pass, new SecureBootCheck().Run(SecureBoot(FirmwareKind.Uefi, 1)).Status);
    }

    [TestMethod]
    public void SecureBoot_Off_Fails()
    {
        CheckOutcome outcome = new SecureBootCheck().Run(SecureBoot(FirmwareKind.Uefi, 0));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        Assert.AreEqual("Secure Boot is off.", outcome.Summary);
    }

    [TestMethod]
    public void SecureBoot_LegacyBios_Fails_WithThatReason()
    {
        CheckOutcome outcome = new SecureBootCheck().Run(SecureBoot(FirmwareKind.Bios, null));

        Assert.AreEqual(CheckStatus.Fail, outcome.Status);
        StringAssert.Contains(outcome.Summary, "legacy BIOS");
    }

    [TestMethod]
    [DataRow(FirmwareKind.Uefi)]
    [DataRow(FirmwareKind.Unknown)]
    public void SecureBoot_StateNotReported_IsCouldNotCheck(FirmwareKind firmware)
    {
        Assert.AreEqual(CheckStatus.Error, new SecureBootCheck().Run(SecureBoot(firmware, null)).Status);
    }

    [TestMethod]
    public void SecureBoot_FirmwareUnreadable_IsCouldNotCheck()
    {
        Assert.AreEqual(CheckStatus.Error, new SecureBootCheck().Run(new FakeProbes()).Status);
    }

    // TPM

    [TestMethod]
    [DataRow(TpmVersion.Version20, CheckStatus.Pass, "This PC has a TPM 2.0.")]
    [DataRow(TpmVersion.Version12, CheckStatus.Fail, "This PC has an older TPM 1.2.")]
    [DataRow(TpmVersion.None, CheckStatus.Fail, "Windows finds no TPM; it may be switched off in the firmware.")]
    public void Tpm_FollowsWhatWindowsFinds(TpmVersion version, CheckStatus expected, string summary)
    {
        CheckOutcome outcome = new TpmCheck().Run(new FakeProbes { Tpm = ProbeResult<TpmVersion>.Ok(version) });

        Assert.AreEqual(expected, outcome.Status);
        Assert.AreEqual(summary, outcome.Summary);
    }

    [TestMethod]
    public void Tpm_Unreadable_IsCouldNotCheck()
    {
        Assert.AreEqual(CheckStatus.Error, new TpmCheck().Run(new FakeProbes()).Status);
    }

    // Memory integrity and start-up options

    [TestMethod]
    public void MemoryIntegrity_FollowsWhatIsRunning()
    {
        Assert.AreEqual(
            CheckStatus.Pass, new MemoryIntegrityCheck().Run(new FakeProbes { CodeIntegrity = Integrity(memoryIntegrity: true) }).Status);
        Assert.AreEqual(
            CheckStatus.Fail, new MemoryIntegrityCheck().Run(new FakeProbes { CodeIntegrity = Integrity(memoryIntegrity: false) }).Status);
        Assert.AreEqual(CheckStatus.Error, new MemoryIntegrityCheck().Run(new FakeProbes()).Status);
    }

    [TestMethod]
    [DataRow(false, false, CheckStatus.Pass, "Windows was started with its normal protections.")]
    [DataRow(true, false, CheckStatus.Fail, "Windows accepts test-signed drivers.")]
    [DataRow(false, true, CheckStatus.Fail, "Kernel debugging is on.")]
    [DataRow(true, true, CheckStatus.Fail, "Windows accepts test-signed drivers and kernel debugging is on.")]
    public void BootOptions_FailOnEitherDeveloperMode(bool testSigning, bool debugging, CheckStatus expected, string summary)
    {
        CheckOutcome outcome = new BootOptionsCheck().Run(new FakeProbes { CodeIntegrity = Integrity(testSigning, debugging) });

        Assert.AreEqual(expected, outcome.Status);
        Assert.AreEqual(summary, outcome.Summary);
        Assert.AreEqual(2, outcome.Findings.Count);
    }

    [TestMethod]
    public void BootOptions_Unreadable_IsCouldNotCheck()
    {
        Assert.AreEqual(CheckStatus.Error, new BootOptionsCheck().Run(new FakeProbes()).Status);
    }

    // Microsoft Defender

    private static FakeProbes Defender(
        string mode = "Normal", bool? antivirus = true, bool? realTime = true, bool? tamper = true, long? cloud = 2)
    {
        FakeProbes probes = new FakeProbes().WithWmiObjects(
            DefenderCheck.WmiNamespace,
            DefenderCheck.StatusClass,
            FakeProbes.Wmi(
                ("AMRunningMode", mode),
                ("AntivirusEnabled", antivirus),
                ("RealTimeProtectionEnabled", realTime),
                ("IsTamperProtected", tamper)));
        return probes.WithWmiObjects(DefenderCheck.WmiNamespace, DefenderCheck.PreferenceClass, FakeProbes.Wmi(("MAPSReporting", cloud)));
    }

    [TestMethod]
    public void Defender_AllOn_Passes()
    {
        CheckOutcome outcome = new DefenderCheck().Run(Defender());

        Assert.AreEqual(CheckStatus.Pass, outcome.Status);
        Assert.AreEqual(3, outcome.Findings.Count);
    }

    [TestMethod]
    public void Defender_BasicCloudProtection_CountsAsOn()
    {
        Assert.AreEqual(CheckStatus.Pass, new DefenderCheck().Run(Defender(cloud: 1)).Status);
    }

    [TestMethod]
    public void Defender_EachProtectionOff_Fails_AndIsNamed()
    {
        Assert.AreEqual("Microsoft Defender's real-time protection is off.", new DefenderCheck().Run(Defender(realTime: false)).Summary);
        Assert.AreEqual("Microsoft Defender's tamper protection is off.", new DefenderCheck().Run(Defender(tamper: false)).Summary);
        Assert.AreEqual("Microsoft Defender's cloud-delivered protection is off.", new DefenderCheck().Run(Defender(cloud: 0)).Summary);

        CheckOutcome two = new DefenderCheck().Run(Defender(realTime: false, cloud: 0));
        Assert.AreEqual(CheckStatus.Fail, two.Status);
        Assert.AreEqual("Microsoft Defender's real-time protection and cloud-delivered protection are off.", two.Summary);
    }

    [TestMethod]
    [DataRow("Passive")]
    [DataRow("EDR Block Mode")]
    public void Defender_SteppedBackForAnotherAntivirus_DoesNotApply(string mode)
    {
        Assert.AreEqual(CheckStatus.NotApplicable, new DefenderCheck().Run(Defender(mode: mode, realTime: false)).Status);
    }

    [TestMethod]
    public void Defender_AntivirusDisabled_DoesNotApply()
    {
        Assert.AreEqual(CheckStatus.NotApplicable, new DefenderCheck().Run(Defender(antivirus: false, realTime: false)).Status);
    }

    [TestMethod]
    public void Defender_NotPartOfThisWindows_DoesNotApply()
    {
        FakeProbes probes = new FakeProbes().WithWmiFailure(
            DefenderCheck.WmiNamespace, DefenderCheck.StatusClass, ProbeFailure.NotSupported("No such namespace."));

        Assert.AreEqual(CheckStatus.NotApplicable, new DefenderCheck().Run(probes).Status);
    }

    [TestMethod]
    public void Defender_AValueNotReported_IsCouldNotCheck_NeverAPass()
    {
        Assert.AreEqual(CheckStatus.Error, new DefenderCheck().Run(Defender(tamper: null)).Status);
        Assert.AreEqual(CheckStatus.Error, new DefenderCheck().Run(Defender(realTime: null)).Status);
        Assert.AreEqual(CheckStatus.Error, new DefenderCheck().Run(Defender(cloud: null)).Status);
        Assert.AreEqual(CheckStatus.Error, new DefenderCheck().Run(new FakeProbes()).Status);
    }

    [TestMethod]
    public void Defender_NoStatusObject_IsCouldNotCheck()
    {
        FakeProbes probes = new FakeProbes().WithWmiObjects(DefenderCheck.WmiNamespace, DefenderCheck.StatusClass);

        Assert.AreEqual(CheckStatus.Error, new DefenderCheck().Run(probes).Status);
    }

    [TestMethod]
    public void Defender_SettingsNeedAdministrator_SaysSo_ButADefiniteProblemStillFails()
    {
        FakeProbes probes = Defender().WithWmiFailure(
            DefenderCheck.WmiNamespace, DefenderCheck.PreferenceClass, ProbeFailure.AccessDenied());
        Assert.AreEqual(CheckStatus.NeedsAdmin, new DefenderCheck().Run(probes).Status);

        FakeProbes withProblem = Defender(realTime: false).WithWmiFailure(
            DefenderCheck.WmiNamespace, DefenderCheck.PreferenceClass, ProbeFailure.AccessDenied());
        Assert.AreEqual(CheckStatus.Fail, new DefenderCheck().Run(withProblem).Status);
    }
}
