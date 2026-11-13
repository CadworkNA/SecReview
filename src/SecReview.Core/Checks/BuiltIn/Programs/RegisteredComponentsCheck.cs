using System.Globalization;
using SecReview.Probing;

namespace SecReview.Checks.BuiltIn.Programs;

/// <summary>
/// Windows keeps lists, for the whole PC, of code that programs pick up without being told
/// where it is: components loaded on request,
/// libraries loaded into every program that opens a window, debuggers started in place of a
/// program, print monitors loaded by the print service, and programs found by their short
/// name. An entry that points at a file a standard user can change puts that user's code into
/// whatever loads it, including programs an administrator or Windows itself runs. Entries each
/// user registers for themselves are not judged.
/// </summary>
public sealed class RegisteredComponentsCheck : ICheck
{
    public const string Id = "system.registered";

    internal const string AppPathsKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths";
    internal const string AppPaths32Key = @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths";
    internal const string ClassesKey = @"SOFTWARE\Classes\CLSID";
    internal const string Classes32Key = @"SOFTWARE\Classes\WOW6432Node\CLSID";
    internal const string DebuggersKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
    internal const string Debuggers32Key = @"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
    internal const string WindowsKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";
    internal const string Windows32Key = @"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows";
    internal const string PrintMonitorsKey = @"SYSTEM\CurrentControlSet\Control\Print\Monitors";

    /// <summary>The most components read under one key. A PC with more gets "could not check", not a partial answer.</summary>
    internal const int MaximumClasses = 60_000;

    /// <summary>How long the reading may take before the check gives up, well inside the limit for one check.</summary>
    internal static readonly TimeSpan Deadline = TimeSpan.FromSeconds(12);

    private const string What = "the registered components";

    public CheckDefinition Definition { get; } = new(
        Id, CheckCategory.SystemIntegrity, Severity.Medium, AdminNeed.ForFullDetail, CheckScope.Machine, KeepsAdministratorAnswer: true);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (MachineContext.Load(context.Probes, out MachineContext machine) is { } failed)
        {
            return failed;
        }

        var sweep = new Sweep(context, machine);
        sweep.Libraries(WindowsKey, "AppInit_DLLs", "Library loaded into every program", view32: false);
        sweep.Libraries(Windows32Key, "AppInit_DLLs", "Library loaded into every program", view32: true);
        return sweep.Each(DebuggersKey, "Debugger", "Debugger for", CommandForm.CommandLine, view32: false)
            ?? sweep.Each(Debuggers32Key, "Debugger", "Debugger for", CommandForm.CommandLine, view32: true)
            ?? sweep.Each(PrintMonitorsKey, "Driver", "Print monitor:", CommandForm.PathOnly, view32: false)
            ?? sweep.Each(AppPathsKey, string.Empty, "App path:", CommandForm.PathOnly, view32: false)
            ?? sweep.Each(AppPaths32Key, string.Empty, "App path:", CommandForm.PathOnly, view32: true)
            ?? sweep.Components(ClassesKey, view32: false)
            ?? sweep.Components(Classes32Key, view32: true)
            ?? sweep.Outcome();
    }

    /// <summary>One run over all the lists. Each distinct file is judged and reported once.</summary>
    private sealed class Sweep(CheckContext context, MachineContext machine)
    {
        private readonly IRegistryProbe _registry = context.Probes.Registry;
        private readonly ProgramJudge _judge = new(context.Probes.Access);
        private readonly EntryReport _report = new("registered component", "registered components", context.IsElevated);
        private readonly HashSet<string> _seen = new(StringComparer.OrdinalIgnoreCase);
        private readonly long _started = context.Clock.GetTimestamp();
        private readonly Dictionary<string, (string Item, string Source, HashSet<string> Items)> _causes = new(StringComparer.OrdinalIgnoreCase);
        private readonly List<string> _causesInOrder = [];
        private int _leftBehind;
        private int _perUser;

        /// <summary>One named value of every key directly below a key: each names a program or library.</summary>
        public CheckOutcome? Each(string key, string valueName, string label, CommandForm form, bool view32)
        {
            ProbeResult<IReadOnlyList<string>> names = _registry.GetSubKeyNames(RegistryRoot.LocalMachine, key);
            if (names.Status == ProbeStatus.NotFound)
            {
                return null;
            }

            if (!names.IsOk)
            {
                return ProbeOutcomes.FromFailure(names, What);
            }

            foreach (string name in names.Value!)
            {
                context.Cancellation.ThrowIfCancellationRequested();
                Add($"{label} {name}", $@"{key}\{name}", valueName, form, view32);
            }

            return null;
        }

        /// <summary>One value that lists several libraries, separated by spaces or commas.</summary>
        public void Libraries(string key, string valueName, string item, bool view32)
        {
            if (Text(key, valueName, item) is not { } text)
            {
                return;
            }

            string[] libraries = text.Contains('"', StringComparison.Ordinal) ? [text] : text.Split([' ', ','], StringSplitOptions.RemoveEmptyEntries);
            foreach (string library in libraries)
            {
                Judge(item, library, $@"HKLM\{key}", CommandForm.PathOnly, view32);
            }
        }

        public CheckOutcome? Components(string key, bool view32)
        {
            ProbeResult<IReadOnlyList<string>> classes = _registry.GetSubKeyNames(RegistryRoot.LocalMachine, key);
            if (classes.Status == ProbeStatus.NotFound)
            {
                return null;
            }

            if (!classes.IsOk)
            {
                return ProbeOutcomes.FromFailure(classes, What);
            }

            if (classes.Value!.Count > MaximumClasses)
            {
                return CheckOutcome.Error(string.Create(
                    CultureInfo.InvariantCulture, $"More than {MaximumClasses} components are registered; they were not read."));
            }

            foreach (string id in classes.Value)
            {
                context.Cancellation.ThrowIfCancellationRequested();
                if (context.Clock.GetElapsedTime(_started) > Deadline)
                {
                    return CheckOutcome.Error("Reading the registered components took too long; they were not all read.");
                }

                Add($"Component {id}", $@"{key}\{id}\InprocServer32", string.Empty, CommandForm.PathOnly, view32);
                Add($"Component {id}", $@"{key}\{id}\LocalServer32", string.Empty, CommandForm.CommandLine, view32);
            }

            return null;
        }

        public CheckOutcome Outcome()
        {
            // One folder with the wrong permissions is one thing to fix, however many entries point into it.
            foreach (string cause in _causesInOrder)
            {
                (string item, string source, HashSet<string> items) = _causes[cause];
                _report.Problem(
                    items.Count == 1 ? item : string.Create(CultureInfo.InvariantCulture, $"{item} and {items.Count - 1} more"),
                    cause,
                    source,
                    items.Count);
            }

            if (_leftBehind > 0)
            {
                _report.Note("Left behind", string.Create(
                    CultureInfo.InvariantCulture, $"{_leftBehind} {(_leftBehind == 1 ? "entry points" : "entries point")} to a file that is not there"));
            }

            if (_perUser > 0)
            {
                _report.Note("Each user's own", string.Create(
                    CultureInfo.InvariantCulture, $"{_perUser} {(_perUser == 1 ? "entry points" : "entries point")} into the user's own folders; not judged"));
            }

            return _report.Outcome("No components are registered for the whole PC.");
        }

        private void Add(string item, string key, string valueName, CommandForm form, bool view32)
        {
            if (Text(key, valueName, item) is { } text)
            {
                Judge(item, text, $@"HKLM\{key}", form, view32);
            }
        }

        private void Judge(string item, string text, string source, CommandForm form, bool view32)
        {
            if (!_seen.Add($"{form}|{view32}|{text}"))
            {
                return;
            }

            ProgramReference reference = ProgramReference.Parse(text, form, machine, view32);
            if (reference.Kind == ReferenceKind.Empty)
            {
                return;
            }

            CommandVerdict verdict = _judge.Command(reference);
            if (reference.PerUser)
            {
                _perUser++;
                _report.Fine();
            }
            else if (verdict.IsMissing)
            {
                // Uninstalled products leave many of these; nothing is loaded, and nobody but
                // an administrator can put something there.
                _leftBehind++;
                _report.Fine();
            }
            else if (verdict.IsProblem)
            {
                Problem(item, verdict.Cause, source);
            }
            else
            {
                _report.Add(item, verdict, source);
            }
        }

        private void Problem(string item, string cause, string source)
        {
            if (!_causes.TryGetValue(cause, out (string Item, string Source, HashSet<string> Items) known))
            {
                _causes[cause] = known = (item, source, new HashSet<string>(StringComparer.OrdinalIgnoreCase));
                _causesInOrder.Add(cause);
            }

            known.Items.Add(item);
        }

        /// <summary>A text value, or null when there is none. One that cannot be read is recorded as such.</summary>
        private string? Text(string key, string valueName, string item)
        {
            ProbeResult<RegistryValue> value = _registry.GetValue(RegistryRoot.LocalMachine, key, valueName);
            if (value.Status == ProbeStatus.NotFound)
            {
                return null;
            }

            if (!value.IsOk)
            {
                _report.Unread(item, value.Detail ?? "The entry could not be read", value.Status == ProbeStatus.AccessDenied, $@"HKLM\{key}");
                return null;
            }

            return value.Value!.Type == RegistryValueType.Text && value.Value.Text.Trim().Length > 0 ? value.Value.Text : null;
        }
    }
}
