using System.Diagnostics;
using SecReview.Checks;
using SecReview.Probing;

namespace SecReview.Diagnostics;

/// <summary>Whether errors of SecReview itself are reported, and if not, why not.</summary>
public enum ErrorReportsState
{
    /// <summary>
    /// This build has nowhere to send reports: a development build, or one somebody else
    /// compiled. The zero value on purpose: nothing is sent unless everything says so.
    /// </summary>
    NoAddress = 0,

    /// <summary>The organisation has switched reports off for this PC.</summary>
    OffByPolicy,

    /// <summary>The user has switched reports off.</summary>
    OffBySetting,

    On,
}

/// <summary>
/// The rules for reporting errors of SecReview itself. What a report may hold is decided here,
/// apart from the library that sends it, so the rules can be tested: an error's type and where
/// in SecReview it happened, the version of SecReview and of Windows. Never a check's result or
/// finding (which checks fail on which PC is a map of its weaknesses), never the computer's or
/// the user's name, never a path in the user's profile.
/// </summary>
public static class ErrorReports
{
    /// <summary>Where an organisation's settings for SecReview live (under HKEY_LOCAL_MACHINE).</summary>
    public const string PolicyKey = @"SOFTWARE\Policies\SecReview";

    /// <summary>The policy value that switches error reports off when it is not zero.</summary>
    public const string PolicyValue = "NoErrorReports";

    /// <summary>The assembly metadata key the build writes the address for reports under.</summary>
    public const string AddressMetadataKey = "ErrorReportAddress";

    /// <summary>
    /// Where this build sends reports; null for a build without an address (a development
    /// build, or one somebody else compiled), which therefore sends nothing.
    /// </summary>
    public static string? CompiledAddress { get; } =
        System.Reflection.CustomAttributeExtensions.GetCustomAttributes<System.Reflection.AssemblyMetadataAttribute>(typeof(ErrorReports).Assembly)
            .FirstOrDefault(attribute => attribute.Key == AddressMetadataKey)?.Value is { Length: > 0 } address
            ? address
            : null;

    /// <summary>The longest message kept from an error.</summary>
    public const int MaximumMessageLength = 300;

    /// <summary>The longest feedback text sent.</summary>
    public const int MaximumFeedbackLength = 2000;

    /// <summary>
    /// Whether reports are sent. The policy is read first and wins; when it cannot be read,
    /// nothing is sent: an organisation that said no must not be overruled by a failed read.
    /// </summary>
    /// <param name="address">Where reports go; null or empty for a build without one.</param>
    /// <param name="settingOn">The user's own switch.</param>
    /// <param name="registry">How the policy is read.</param>
    public static ErrorReportsState State(string? address, bool settingOn, IRegistryProbe registry)
    {
        ArgumentNullException.ThrowIfNull(registry);
        if (string.IsNullOrWhiteSpace(address))
        {
            return ErrorReportsState.NoAddress;
        }

        ProbeResult<RegistryValue> policy = registry.GetValue(RegistryRoot.LocalMachine, PolicyKey, PolicyValue);
        if (policy.IsOk ? policy.Value is not { Type: RegistryValueType.Number, Number: 0 } : policy.Status != ProbeStatus.NotFound)
        {
            return ErrorReportsState.OffByPolicy;
        }

        return settingOn ? ErrorReportsState.On : ErrorReportsState.OffBySetting;
    }

    /// <summary>The state in a sentence, for the settings dialog.</summary>
    public static string Describe(ErrorReportsState state) => state switch
    {
        ErrorReportsState.On => "On. Only errors of SecReview itself are sent, never results.",
        ErrorReportsState.OffBySetting => "Off.",
        ErrorReportsState.OffByPolicy => "Switched off by your organisation.",
        _ => "This build of SecReview has nowhere to send reports, so nothing is sent.",
    };

    /// <summary>
    /// What may be said about an error besides its type. For an error inside a check: nothing,
    /// because its message can quote what the check was reading. For any other error: the
    /// message with the user's and the computer's name removed, cut to its limit.
    /// </summary>
    public static string? Message(Exception exception, PrivacyFilter privacy, bool fromCheck)
    {
        ArgumentNullException.ThrowIfNull(exception);
        ArgumentNullException.ThrowIfNull(privacy);
        return fromCheck ? null : Text(exception.Message, privacy, MaximumMessageLength);
    }

    /// <summary>A text as it may be sent: names removed, one line, within a limit.</summary>
    public static string Text(string? text, PrivacyFilter privacy, int maximumLength)
    {
        ArgumentNullException.ThrowIfNull(privacy);
        string oneLine = string.Join(' ', (text ?? string.Empty).Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        string scrubbed = privacy.Scrub(oneLine);
        return scrubbed.Length <= maximumLength ? scrubbed : scrubbed[..maximumLength];
    }

    /// <summary>
    /// What tells one error from another for "already reported": its type, where it was thrown
    /// and the check it came from. The message is left out: it differs from PC to PC.
    /// </summary>
    public static string Fingerprint(Exception exception, string? checkId)
    {
        ArgumentNullException.ThrowIfNull(exception);
        // The first line of the stack: the method the error was thrown in.
        string where = exception.StackTrace is { Length: > 0 } stack ? stack.Split('\n')[0].Trim() : string.Empty;
        return $"{exception.GetType().FullName}|{where}|{checkId}";
    }

    /// <summary>
    /// The results as they may go with feedback when the user asks for it: for each check that
    /// did not pass, its identifier and how it ended. No summaries and no findings.
    /// </summary>
    public static string ResultsForFeedback(Scanning.ScanResult scan)
    {
        ArgumentNullException.ThrowIfNull(scan);
        string[] lines =
        [
            .. scan.Checks
                .Where(check => check.Result.Outcome.Status is not (CheckStatus.Pass or CheckStatus.NotApplicable))
                .Select(check => $"{check.Definition.Id}: {check.Result.Outcome.Status}"),
        ];
        int passed = scan.Count(CheckStatus.Pass);
        return lines.Length == 0
            ? $"{passed} checks pass; none fail."
            : $"{passed} checks pass. Not passing:{Environment.NewLine}{string.Join(Environment.NewLine, lines)}";
    }
}

/// <summary>
/// Keeps one process from reporting the same error over and over, or more than a handful in
/// all: a check that fails on every scan is one report, not one per scan.
/// </summary>
public sealed class ErrorReportBudget(int maximum = ErrorReportBudget.DefaultMaximum)
{
    /// <summary>How many reports one run of SecReview sends at most.</summary>
    public const int DefaultMaximum = 20;

    private readonly HashSet<string> _seen = new(StringComparer.Ordinal);
    private readonly Lock _gate = new();

    /// <summary>Whether an error with this fingerprint may be reported now. True at most once per fingerprint.</summary>
    public bool Allow(string fingerprint)
    {
        ArgumentNullException.ThrowIfNull(fingerprint);
        lock (_gate)
        {
            return _seen.Count < maximum && _seen.Add(fingerprint);
        }
    }
}

/// <summary>
/// Tells whether SecReview's previous run ended without closing down: a file is left in the
/// data folder while a window is open and removed when it closes. A file whose process is gone
/// is a run that crashed or was killed.
/// </summary>
public sealed class RunMarker
{
    private readonly string _folder;
    private readonly int _processId;
    private readonly Func<int, bool> _isRunning;

    /// <param name="folder">SecReview's data folder.</param>
    /// <param name="processId">This process.</param>
    /// <param name="isRunning">Whether a process of that number is a running SecReview.</param>
    public RunMarker(string folder, int processId, Func<int, bool> isRunning)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(folder);
        ArgumentNullException.ThrowIfNull(isRunning);
        _folder = folder;
        _processId = processId;
        _isRunning = isRunning;
    }

    /// <summary>The marker for this process, in SecReview's data folder.</summary>
    public static RunMarker ForThisProcess()
    {
        using var self = Process.GetCurrentProcess();
        string name = self.ProcessName;
        return new RunMarker(AppData.Directory, Environment.ProcessId, id =>
        {
            try
            {
                using var other = Process.GetProcessById(id);
                return other.ProcessName.Equals(name, StringComparison.OrdinalIgnoreCase);
            }
            catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
            {
                return false;
            }
        });
    }

    private string Path => System.IO.Path.Combine(_folder, $"running-{_processId}.marker");

    /// <summary>
    /// Marks this run as started. Returns whether an earlier run ended without closing down;
    /// what that run left behind is cleared, so it is said once. Never throws.
    /// </summary>
    public bool Begin()
    {
        bool abnormal = false;
        try
        {
            Directory.CreateDirectory(_folder);
            foreach (string marker in Directory.GetFiles(_folder, "running-*.marker"))
            {
                string number = System.IO.Path.GetFileNameWithoutExtension(marker)["running-".Length..];
                if (!int.TryParse(number, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int id))
                {
                    File.Delete(marker); // not one of ours
                }
                else if (id == _processId || !_isRunning(id))
                {
                    // Its process is gone (or its number has come round to this one): that run never closed down.
                    abnormal = true;
                    File.Delete(marker);
                }
            }

            File.WriteAllText(Path, string.Empty);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Without a marker the next run simply has nothing to say.
        }

        return abnormal;
    }

    /// <summary>Marks this run as closed down. Never throws.</summary>
    public void End()
    {
        try
        {
            File.Delete(Path);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // The next run will take it for a run that did not close down; that is the lesser evil.
        }
    }
}
