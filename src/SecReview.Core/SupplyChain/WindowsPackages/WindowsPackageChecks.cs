using SecReview.Checks;
using SecReview.Config;
using SecReview.Probing;

namespace SecReview.SupplyChain.WindowsPackages;

/// <summary>
/// winget verifies what it installs: the installer's hash, the Microsoft Store's certificate,
/// a malware scan of archives, and manifests only from its sources. Each of these can be
/// switched off by policy; a policy that does is reported, with the note that it comes from
/// the organisation. Switches an administrator set with winget itself are kept where they
/// cannot be read without running winget, and the result says so.
/// </summary>
public sealed class WingetPoliciesCheck : ICheck
{
    public const string Id = "sc.winget.policies";

    internal const string PolicyKey = @"SOFTWARE\Policies\Microsoft\Windows\AppInstaller";

    /// <summary>Policy value, what it weakens, and the words for it when it is on.</summary>
    private static readonly (string Name, string Item, string Found)[] Overrides =
    [
        ("EnableHashOverride", "Installer hash check", "May be skipped"),
        ("EnableLocalManifestFiles", "Installing from a manifest file", "Allowed: any file can say what to download"),
        ("EnableBypassCertificatePinningForMicrosoftStore", "Microsoft Store certificate check", "May be skipped"),
        ("EnableLocalArchiveMalwareScanOverride", "Malware scan of archives", "May be skipped"),
    ];

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.Medium, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        SystemProbes probes = context.Probes;

        ProbeResult<string> local = probes.Environment.Folder(KnownFolder.LocalAppData);
        if (!local.IsOk)
        {
            return CheckOutcome.Error("Windows did not say where your user folders are.");
        }

        var problems = new List<Finding>();
        bool anyPolicy = false;
        foreach ((string name, string item, string found) in Overrides)
        {
            if (RegistryReader.Number(probes.Registry, RegistryRoot.LocalMachine, PolicyKey, name, "winget's policy", out long? value) is { } failed)
            {
                return failed;
            }

            anyPolicy |= value is not null;
            if (value == 1)
            {
                problems.Add(Finding.Problem(item, found, "Always on", $@"HKLM\{PolicyKey}\{name}"));
            }
        }

        // winget comes with Windows as an app alias in the user's folder.
        bool installed = SettingsFiles.Exists(probes.Files, $@"{local.Value}\Microsoft\WindowsApps", "winget.exe");
        if (!installed && !anyPolicy)
        {
            return CheckOutcome.NotApplicable("winget is not installed.");
        }

        if (problems.Count > 0)
        {
            return CheckOutcome.Fail(
                problems.Count == 1
                    ? $"A policy weakens winget: {Wording.LowerFirst(problems[0].Item)}: {Wording.LowerFirst(problems[0].Found)}."
                    : $"{problems.Count} policies weaken what winget verifies before it installs.",
                problems) with { ManagedByPolicy = true };
        }

        return CheckOutcome.Pass(
            "No policy weakens what winget verifies before it installs.",
            Finding.Ok("Policies that let winget skip a check", "None", "None"),
            Finding.Note("Switches set with winget itself", "Not readable without running winget; \"winget settings export\" shows them"));
    }
}

/// <summary>
/// Chocolatey must verify what it downloads: checksums on, packages without a checksum
/// refused, and no source over plain HTTP. Its settings file is read; Chocolatey is not run.
/// </summary>
public sealed class ChocolateySettingsCheck : ICheck
{
    public const string Id = "sc.choco.settings";

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.Medium, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        SystemProbes probes = context.Probes;

        ProbeResult<string> programData = probes.Environment.Folder(KnownFolder.ProgramData);
        if (!programData.IsOk)
        {
            return CheckOutcome.Error("Windows did not say where its shared folder is.");
        }

        if (PersistentEnvironment.Read(probes, "ChocolateyInstall", out string? install, out _) is { } failed)
        {
            return failed;
        }

        string path = $@"{install?.Trim().TrimEnd('\\', '/') ?? programData.Value + @"\chocolatey"}\config\chocolatey.config";
        XmlFile? file = XmlFiles.Load(probes.Files, path);
        if (file is null)
        {
            return CheckOutcome.NotApplicable("Chocolatey is not installed.");
        }

        if (file.Root is not { } root)
        {
            return CheckOutcome.Error(file.Problem!);
        }

        var problems = new List<Finding>();
        var findings = new List<Finding>();
        foreach (MarkupElement feature in root.Child("features")?.ChildrenNamed("feature") ?? [])
        {
            bool enabled = string.Equals(feature.Attribute("enabled"), "true", StringComparison.OrdinalIgnoreCase);
            switch (feature.Attribute("name")?.ToLowerInvariant())
            {
                case "checksumfiles" when !enabled:
                    problems.Add(Finding.Problem("Checksum verification", "Off", "On", file.At(feature)));
                    break;
                case "allowemptychecksums" when enabled:
                    problems.Add(Finding.Problem("Packages without a checksum", "Allowed, over plain HTTP too", "Refused", file.At(feature)));
                    break;
                case "allowemptychecksumssecure" when enabled:
                    // Chocolatey's own default: tolerated, but worth knowing.
                    findings.Add(Finding.Note("Packages without a checksum, over HTTPS", "Allowed (Chocolatey's default)", file.At(feature)));
                    break;
            }
        }

        foreach (MarkupElement source in root.Child("sources")?.ChildrenNamed("source") ?? [])
        {
            bool disabled = string.Equals(source.Attribute("disabled"), "true", StringComparison.OrdinalIgnoreCase);
            if (!disabled && source.Attribute("value")?.TrimStart().StartsWith("http://", StringComparison.OrdinalIgnoreCase) == true)
            {
                problems.Add(Finding.Problem($"Source \"{source.Attribute("id")}\"", "Plain HTTP", "HTTPS", file.At(source)));
            }
        }

        if (problems.Count > 0)
        {
            return CheckOutcome.Fail(
                problems.Count == 1
                    ? $"Chocolatey: {Wording.LowerFirst(problems[0].Item)}: {Wording.LowerFirst(problems[0].Found)}."
                    : $"Chocolatey has {problems.Count} settings that weaken what it verifies.",
                [.. problems, .. findings]);
        }

        findings.Insert(0, Finding.Ok("Checksum verification", "On", "On"));
        return CheckOutcome.Pass("Chocolatey verifies checksums and uses HTTPS sources.", findings);
    }
}
