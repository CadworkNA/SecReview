using SecReview.Probing;

namespace SecReview.Checks.BuiltIn.Programs;

/// <summary>
/// Services and drivers run with full control of the PC, before anyone signs in. A standard
/// user who can replace a service's program, put one where Windows looks first (a path with
/// spaces written without quotes), or rewrite the service's settings, gets that control. The
/// programs are read from the services' settings in the registry; no service is asked anything.
/// </summary>
public sealed class ServiceProgramsCheck : ICheck
{
    public const string Id = "system.services";

    internal const string ServicesKey = @"SYSTEM\CurrentControlSet\Services";

    private const long KernelDriver = 0x1;
    private const long FileSystemDriver = 0x2;
    private const long UserServiceInstance = 0x80;
    private const long Disabled = 4;

    public CheckDefinition Definition { get; } = new(
        Id, CheckCategory.SystemIntegrity, Severity.High, AdminNeed.ForFullDetail, CheckScope.Machine, KeepsAdministratorAnswer: true);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (MachineContext.Load(context.Probes, out MachineContext machine) is { } failed)
        {
            return failed;
        }

        IRegistryProbe registry = context.Probes.Registry;
        ProbeResult<IReadOnlyList<string>> services = registry.GetSubKeyNames(RegistryRoot.LocalMachine, ServicesKey);
        if (!services.IsOk)
        {
            return ProbeOutcomes.FromFailure(services, "the list of services");
        }

        var judge = new ProgramJudge(context.Probes.Access);
        var report = new EntryReport("service program", "service programs", context.IsElevated);
        foreach (string name in services.Value!)
        {
            context.Cancellation.ThrowIfCancellationRequested();
            Add(report, judge, machine, registry, name);
        }

        return report.Outcome("No service is installed.");
    }

    private static void Add(EntryReport report, ProgramJudge judge, MachineContext machine, IRegistryProbe registry, string name)
    {
        string key = $@"{ServicesKey}\{name}";
        string source = $@"HKLM\{key}";

        // A key without a type holds settings for something else, not a service. A service
        // made for one signed-in user is a copy of one that is judged.
        ProbeResult<RegistryValue> kind = registry.GetValue(RegistryRoot.LocalMachine, key, "Type");
        if (!kind.IsOk && kind.Status != ProbeStatus.NotFound)
        {
            report.Unread($"Service: {name}", kind.Detail ?? "Its settings could not be read", kind.Status == ProbeStatus.AccessDenied, source);
            return;
        }

        if (kind is not { IsOk: true, Value.Type: RegistryValueType.Number } || (kind.Value.Number & UserServiceInstance) != 0)
        {
            return;
        }

        long type = kind.Value.Number;
        bool driver = (type & (KernelDriver | FileSystemDriver)) != 0;
        string item = $"{(driver ? "Driver" : "Service")}: {name}";
        ProbeResult<RegistryValue> image = registry.GetValue(RegistryRoot.LocalMachine, key, "ImagePath");
        if (image.Status == ProbeStatus.NotFound)
        {
            return;
        }

        if (image is not { IsOk: true, Value.Type: RegistryValueType.Text })
        {
            report.Unread(item, image.IsOk ? "Its program is not stored as text" : image.Detail ?? "Its program could not be read", image.Status == ProbeStatus.AccessDenied, source);
            return;
        }

        ProgramReference reference = ProgramReference.Parse(image.Value.Text, CommandForm.ServiceImage, machine);
        if (reference.Kind == ReferenceKind.Empty)
        {
            return;
        }

        // A service hosted by Windows names its own library in its settings.
        if (!driver && reference is { Kind: ReferenceKind.Local, Target: null } &&
            Path.GetFileName(reference.Candidates[^1]).Equals("svchost.exe", StringComparison.OrdinalIgnoreCase))
        {
            if (Library(registry, key, out string? library) is { } unread)
            {
                report.Unread(item, "Its library is named where only an administrator can read", unread == ProbeStatus.AccessDenied, source);
                return;
            }

            if (library is not null)
            {
                reference = reference with { Target = ProgramReference.Parse(library, CommandForm.PathOnly, machine), CommandOnly = false };
            }
        }

        bool disabled = Number(registry, key, "Start") == Disabled;
        CommandVerdict verdict = judge.Command(reference);
        Verdict settings = judge.Key(RegistryRoot.LocalMachine, key);
        if (disabled && (verdict.IsProblem || settings.IsProblem))
        {
            // Nothing starts it as it is; whoever enables it should know.
            report.Fine();
            report.Note(item, $"Disabled. {(verdict.IsProblem ? verdict.Found : settings.Found)}", source);
        }
        else if (settings.IsProblem && !verdict.IsProblem)
        {
            report.Problem(item, settings.Found, source);
        }
        else if (driver && verdict.IsMissing)
        {
            // Windows keeps settings for drivers of devices that are not connected.
            report.Fine();
        }
        else
        {
            report.Add(item, verdict, source);
            if (settings.Kind == VerdictKind.Unknown && !verdict.IsProblem && !verdict.IsUnknown)
            {
                report.Unread(item, settings.Found, settings.NeedsAdministrator, source);
            }
        }
    }

    /// <summary>The library a hosted service names, or null. Returns how the read ended when it failed.</summary>
    private static ProbeStatus? Library(IRegistryProbe registry, string key, out string? library)
    {
        library = null;
        foreach (string place in (string[])[$@"{key}\Parameters", key])
        {
            ProbeResult<RegistryValue> value = registry.GetValue(RegistryRoot.LocalMachine, place, "ServiceDll");
            if (value is { IsOk: true, Value.Type: RegistryValueType.Text } && value.Value.Text.Trim().Length > 0)
            {
                library = value.Value.Text;
                return null;
            }

            if (!value.IsOk && value.Status != ProbeStatus.NotFound)
            {
                return value.Status;
            }
        }

        return null;
    }

    private static long? Number(IRegistryProbe registry, string key, string name) =>
        registry.GetValue(RegistryRoot.LocalMachine, key, name) is { IsOk: true, Value.Type: RegistryValueType.Number } value
            ? value.Value.Number
            : null;
}
