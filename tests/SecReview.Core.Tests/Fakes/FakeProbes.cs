using SecReview.Probing;

namespace SecReview.Tests.Fakes;

/// <summary>
/// Stand-ins for the machine. Each returns what the test set. A reading the test did not set
/// fails outright, so a check that reads more than its test expects shows up as a failure
/// rather than as a plausible result. A registry value or service that was not added is
/// "not found", as on a real machine.
/// </summary>
internal sealed class FakeProbes
{
    private static readonly ProbeFailure NotSetUp = ProbeFailure.Failed("Not set up in this test.");

    private readonly Dictionary<string, ProbeResult<RegistryValue>> _registryValues =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly Dictionary<string, ProbeResult<ServiceInfo>> _services = new(StringComparer.OrdinalIgnoreCase);

    public ProbeResult<FirewallState> Firewall { get; set; } = NotSetUp;

    public ProbeResult<IReadOnlyList<SecurityProduct>> AntivirusProducts { get; set; } = NotSetUp;

    public ProbeResult<IReadOnlyList<SecurityProduct>> FirewallProducts { get; set; } = NotSetUp;

    public ProbeResult<AccountPolicy> AccountPolicy { get; set; } = NotSetUp;

    public ProbeResult<PowerSettings> Power { get; set; } = NotSetUp;

    public ProbeResult<IReadOnlyList<DriveEncryption>> DriveEncryption { get; set; } = NotSetUp;

    public ProbeResult<WindowsUpdateStatus> WindowsUpdate { get; set; } = NotSetUp;

    /// <summary>The setting every asked-for audit subcategory has, or the failure of the read.</summary>
    public ProbeResult<AuditSetting> AuditPolicy { get; set; } = NotSetUp;

    /// <summary>When set, every registry read ends this way (for example access denied).</summary>
    public ProbeFailure? RegistryFailure { get; set; }

    private readonly Dictionary<string, ProbeResult<IReadOnlyList<WmiObject>>> _wmiClasses =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly Dictionary<string, ProbeResult<IReadOnlyList<AccountReference>>> _userRights =
        new(StringComparer.OrdinalIgnoreCase);

    public FakeProbes WithWmiObjects(string wmiNamespace, string className, params WmiObject[] objects)
    {
        _wmiClasses[$"{wmiNamespace}:{className}"] = ProbeResult<IReadOnlyList<WmiObject>>.Ok(objects);
        return this;
    }

    public FakeProbes WithWmiFailure(string wmiNamespace, string className, ProbeFailure failure)
    {
        _wmiClasses[$"{wmiNamespace}:{className}"] = failure;
        return this;
    }

    public FakeProbes WithUserRight(string right, params AccountReference[] accounts)
    {
        _userRights[right] = ProbeResult<IReadOnlyList<AccountReference>>.Ok(accounts);
        return this;
    }

    public FakeProbes WithUserRightFailure(string right, ProbeFailure failure)
    {
        _userRights[right] = failure;
        return this;
    }

    /// <summary>The made-up user profile every fake path hangs under.</summary>
    public const string UserProfile = @"C:\Users\tester";

    private readonly Dictionary<string, ProbeResult<string>> _files = new(StringComparer.OrdinalIgnoreCase);

    private readonly Dictionary<string, ProbeFailure> _folderFailures = new(StringComparer.OrdinalIgnoreCase);

    private readonly Dictionary<string, string> _variables = new(StringComparer.OrdinalIgnoreCase);

    public ProbeResult<FirmwareKind> Firmware { get; set; } = NotSetUp;

    public ProbeResult<TpmVersion> Tpm { get; set; } = NotSetUp;

    public ProbeResult<CodeIntegrityState> CodeIntegrity { get; set; } = NotSetUp;

    /// <summary>How long Windows has been running.</summary>
    public ProbeResult<TimeSpan> Uptime { get; set; } = NotSetUp;

    /// <summary>When the fake files were last changed.</summary>
    public DateTimeOffset FileTime { get; set; } = new(2026, 1, 10, 12, 0, 0, TimeSpan.Zero);

    /// <summary>When set, every service read ends this way.</summary>
    public ProbeFailure? ServicesFailure { get; set; }

    /// <summary>When set, every file and folder read ends this way (for example access denied).</summary>
    public ProbeFailure? FilesFailure { get; set; }

    /// <summary>A text file. Its folders exist from then on.</summary>
    public FakeProbes WithFile(string path, string text)
    {
        _files[path] = ProbeResult<string>.Ok(text);
        return this;
    }

    /// <summary>A file that is there but cannot be read (access denied, too large, not text).</summary>
    public FakeProbes WithFileFailure(string path, ProbeFailure failure)
    {
        _files[path] = failure;
        return this;
    }

    /// <summary>A folder that cannot be listed.</summary>
    public FakeProbes WithFolderFailure(string directory, ProbeFailure failure)
    {
        _folderFailures[directory.TrimEnd('\\')] = failure;
        return this;
    }

    public FakeProbes WithVariable(string name, string value)
    {
        _variables[name] = value;
        return this;
    }

    /// <summary>Where a known folder is on the fake PC.</summary>
    public static string FolderPath(KnownFolder folder) => folder switch
    {
        KnownFolder.UserProfile => UserProfile,
        KnownFolder.RoamingAppData => UserProfile + @"\AppData\Roaming",
        KnownFolder.LocalAppData => UserProfile + @"\AppData\Local",
        KnownFolder.ProgramData => @"C:\ProgramData",
        KnownFolder.ProgramFiles => @"C:\Program Files",
        KnownFolder.ProgramFilesX86 => @"C:\Program Files (x86)",
        _ => @"C:\Windows",
    };

    /// <summary>A WMI object with the given property values.</summary>
    public static WmiObject Wmi(params (string Name, object? Value)[] properties) =>
        new(properties.Select(p => new KeyValuePair<string, object?>(p.Name, p.Value)));

    public FakeProbes WithRegistryValue(RegistryRoot root, string keyPath, string valueName, RegistryValue value)
    {
        _registryValues[RegistryPath(root, keyPath, valueName)] = ProbeResult<RegistryValue>.Ok(value);
        return this;
    }

    public FakeProbes WithRegistryNumber(RegistryRoot root, string keyPath, string valueName, long value) =>
        WithRegistryValue(root, keyPath, valueName, RegistryValue.FromNumber(value));

    public FakeProbes WithoutRegistryValue(RegistryRoot root, string keyPath, string valueName)
    {
        _registryValues.Remove(RegistryPath(root, keyPath, valueName));
        return this;
    }

    public FakeProbes WithoutService(string name)
    {
        _services.Remove(name);
        return this;
    }

    public FakeProbes WithService(string name, ServiceStartType startType, bool isRunning)
    {
        _services[name] = ProbeResult<ServiceInfo>.Ok(new ServiceInfo(name, startType, isRunning));
        return this;
    }

    public FakeProbes WithServiceFailure(string name, ProbeFailure failure)
    {
        _services[name] = failure;
        return this;
    }

    public SystemProbes Build() => new(
        Registry: new RegistryProbe(this),
        Services: new ServiceProbe(this),
        Wmi: new WmiProbe(this),
        Firewall: new FirewallProbe(this),
        SecurityCenter: new SecurityCenterProbe(this),
        AccountPolicy: new AccountPolicyProbe(this),
        Power: new PowerProbe(this),
        DriveEncryption: new DriveEncryptionProbe(this),
        WindowsUpdate: new WindowsUpdateProbe(this),
        AuditPolicy: new AuditPolicyProbe(this),
        UserRights: new UserRightsProbe(this),
        Files: new FileProbe(this),
        Environment: new EnvironmentProbe(this),
        Platform: new PlatformProbe(this));

    /// <summary>A firewall state with all three profiles set the same way.</summary>
    public static FirewallState FirewallAll(bool enabled, bool blocksInbound = true) => new(
        [
            new FirewallProfileState(FirewallProfiles.Domain, enabled, blocksInbound),
            new FirewallProfileState(FirewallProfiles.Private, enabled, blocksInbound),
            new FirewallProfileState(FirewallProfiles.Public, enabled, blocksInbound),
        ],
        FirewallProfiles.Private);

    public static AccountPolicy DefaultAccountPolicy() => new(
        MinimumPasswordLength: 0,
        MaximumPasswordAge: TimeSpan.FromDays(42),
        MinimumPasswordAge: TimeSpan.Zero,
        PasswordHistoryLength: 0,
        LockoutThreshold: 10,
        LockoutDuration: TimeSpan.FromMinutes(10),
        LockoutObservationWindow: TimeSpan.FromMinutes(10));

    /// <summary>A laptop whose display turns off after the given minutes on either power source.</summary>
    public static PowerSettings Laptop(int displayOffMinutes, bool requirePasswordOnWake = true, bool modernStandby = false)
    {
        var source = new PowerSourceSettings(
            DisplayOff: TimeSpan.FromMinutes(displayOffMinutes),
            Sleep: TimeSpan.FromMinutes(30),
            RequirePasswordOnWake: requirePasswordOnWake);
        return new PowerSettings(PluggedIn: source, OnBattery: source, HasBattery: true, ModernStandby: modernStandby);
    }

    private static string RegistryPath(RegistryRoot root, string keyPath, string valueName) =>
        $"{root}\\{keyPath.Trim('\\')}\\\\{valueName}";

    private sealed class RegistryProbe(FakeProbes owner) : IRegistryProbe
    {
        public ProbeResult<RegistryValue> GetValue(RegistryRoot root, string keyPath, string valueName)
        {
            if (owner.RegistryFailure is { } failure)
            {
                return failure;
            }

            return owner._registryValues.TryGetValue(RegistryPath(root, keyPath, valueName), out var value)
                ? value
                : ProbeFailure.NotFound();
        }

        public ProbeResult<IReadOnlyList<string>> GetSubKeyNames(RegistryRoot root, string keyPath) =>
            Names(root, keyPath, subKeys: true);

        public ProbeResult<IReadOnlyList<string>> GetValueNames(RegistryRoot root, string keyPath) =>
            Names(root, keyPath, subKeys: false);

        private ProbeResult<IReadOnlyList<string>> Names(RegistryRoot root, string keyPath, bool subKeys)
        {
            if (owner.RegistryFailure is { } failure)
            {
                return failure;
            }

            // Stored paths look like "Root\key\path\\valueName".
            string prefix = $"{root}\\{keyPath.Trim('\\')}\\";
            var names = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string path in owner._registryValues.Keys)
            {
                if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                string rest = path[prefix.Length..];
                bool isValueOfThisKey = rest.StartsWith('\\');
                if (!subKeys && isValueOfThisKey)
                {
                    names.Add(rest[1..]);
                }
                else if (subKeys && !isValueOfThisKey)
                {
                    names.Add(rest[..rest.IndexOf('\\', StringComparison.Ordinal)]);
                }
            }

            return names.Count == 0 && !owner._registryValues.Keys.Any(
                    path => path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                ? ProbeFailure.NotFound()
                : ProbeResult<IReadOnlyList<string>>.Ok([.. names]);
        }
    }

    private sealed class ServiceProbe(FakeProbes owner) : IServiceProbe
    {
        public ProbeResult<ServiceInfo> GetService(string name) =>
            owner.ServicesFailure is { } failure ? failure
            : owner._services.TryGetValue(name, out var service) ? service
            : ProbeFailure.NotFound();
    }

    private sealed class FirewallProbe(FakeProbes owner) : IFirewallProbe
    {
        public ProbeResult<FirewallState> GetState() => owner.Firewall;
    }

    private sealed class SecurityCenterProbe(FakeProbes owner) : ISecurityCenterProbe
    {
        public ProbeResult<IReadOnlyList<SecurityProduct>> GetProducts(SecurityProductKind kind) =>
            kind == SecurityProductKind.Antivirus ? owner.AntivirusProducts : owner.FirewallProducts;
    }

    private sealed class AccountPolicyProbe(FakeProbes owner) : IAccountPolicyProbe
    {
        public ProbeResult<AccountPolicy> GetPolicy() => owner.AccountPolicy;
    }

    private sealed class PowerProbe(FakeProbes owner) : IPowerProbe
    {
        public ProbeResult<PowerSettings> GetSettings() => owner.Power;
    }

    private sealed class DriveEncryptionProbe(FakeProbes owner) : IDriveEncryptionProbe
    {
        public ProbeResult<IReadOnlyList<DriveEncryption>> GetFixedDrives() => owner.DriveEncryption;
    }

    private sealed class WindowsUpdateProbe(FakeProbes owner) : IWindowsUpdateProbe
    {
        public ProbeResult<WindowsUpdateStatus> GetStatus() => owner.WindowsUpdate;
    }

    private sealed class WmiProbe(FakeProbes owner) : IWmiProbe
    {
        public ProbeResult<IReadOnlyList<WmiObject>> Query(
            string wmiNamespace, string className, IReadOnlyList<string> properties, WmiFlagFilter? only = null)
        {
            if (!owner._wmiClasses.TryGetValue($"{wmiNamespace}:{className}", out var result))
            {
                return NotSetUp;
            }

            // As WMI does: only the instances whose flag has the asked-for value.
            return only is null || !result.IsOk
                ? result
                : ProbeResult<IReadOnlyList<WmiObject>>.Ok([.. result.Value!.Where(o => o.Flag(only.Property) == only.Value)]);
        }
    }

    private sealed class AuditPolicyProbe(FakeProbes owner) : IAuditPolicyProbe
    {
        public ProbeResult<IReadOnlyDictionary<Guid, AuditSetting>> GetSubcategories(
            IReadOnlyList<Guid> subcategories)
        {
            if (!owner.AuditPolicy.IsOk)
            {
                return owner.AuditPolicy.ToFailure();
            }

            return ProbeResult<IReadOnlyDictionary<Guid, AuditSetting>>.Ok(
                subcategories.ToDictionary(id => id, _ => owner.AuditPolicy.Value));
        }
    }

    private sealed class UserRightsProbe(FakeProbes owner) : IUserRightsProbe
    {
        public ProbeResult<IReadOnlyList<AccountReference>> GetAccountsWithRight(string right) =>
            owner._userRights.TryGetValue(right, out var result) ? result : NotSetUp;
    }

    /// <summary>Files held in memory. A file or folder that was not added is "not found", as on disk.</summary>
    private sealed class FileProbe(FakeProbes owner) : IFileProbe
    {
        public ProbeResult<string> ReadText(string path, int maximumBytes = IFileProbe.DefaultMaximumBytes)
        {
            if (owner.FilesFailure is { } everything)
            {
                return everything;
            }

            if (!owner._files.TryGetValue(path, out ProbeResult<string> file))
            {
                return ProbeFailure.NotFound();
            }

            return file.IsOk && file.Value!.Length > maximumBytes
                ? ProbeFailure.Failed($"The file is larger than {maximumBytes / 1024} KB and was not read.")
                : file;
        }

        public ProbeResult<IReadOnlyList<FileEntry>> List(string directory)
        {
            if (owner.FilesFailure is { } everything)
            {
                return everything;
            }

            string folder = directory.TrimEnd('\\');
            if (owner._folderFailures.TryGetValue(folder, out ProbeFailure failure))
            {
                return failure;
            }

            string prefix = folder + "\\";
            var entries = new SortedDictionary<string, FileEntry>(StringComparer.OrdinalIgnoreCase);
            foreach ((string path, ProbeResult<string> file) in owner._files)
            {
                if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                string rest = path[prefix.Length..];
                int separator = rest.IndexOf('\\', StringComparison.Ordinal);
                string name = separator < 0 ? rest : rest[..separator];
                entries[name] = new FileEntry(
                    name,
                    IsDirectory: separator >= 0,
                    IsLink: false,
                    Length: separator >= 0 ? 0 : file.IsOk ? file.Value!.Length : 100,
                    LastWrite: owner.FileTime);
            }

            return entries.Count == 0
                ? ProbeFailure.NotFound()
                : ProbeResult<IReadOnlyList<FileEntry>>.Ok([.. entries.Values]);
        }
    }

    private sealed class PlatformProbe(FakeProbes owner) : IPlatformProbe
    {
        public ProbeResult<FirmwareKind> GetFirmware() => owner.Firmware;

        public ProbeResult<TpmVersion> GetTpm() => owner.Tpm;

        public ProbeResult<CodeIntegrityState> GetCodeIntegrity() => owner.CodeIntegrity;
    }

    private sealed class EnvironmentProbe(FakeProbes owner) : IEnvironmentProbe
    {
        public ProbeResult<string> Folder(KnownFolder folder) => ProbeResult<string>.Ok(FolderPath(folder));

        public string? Variable(string name) => owner._variables.GetValueOrDefault(name);

        public ProbeResult<TimeSpan> Uptime() => owner.Uptime;
    }
}
