using System.Reflection;
using Sentry;
using Sentry.Extensibility;
using Sentry.Protocol;
using Sentry.Protocol.Envelopes;
using SecReview.Checks;
using SecReview.Diagnostics;
using SecReview.Probing;

namespace SecReview.App;

/// <summary>
/// Reports errors of SecReview itself, through the Sentry SDK. What may be reported, and
/// whether anything is, is decided by <see cref="ErrorReports"/>; this class only carries it
/// out. Nothing is started, and so nothing can be sent, unless the build has an address, the
/// organisation allows it and the user is known to have left it on.
/// </summary>
/// <remarks>
/// Every report passes through <see cref="Clean"/> on its way out, whatever raised it, and
/// what leaves is not the report the SDK made but a new one, filled with the few things that
/// are allowed: the error's type and stack, the check it came from, the versions of Windows
/// and .NET. Anything the SDK adds, now or in a later version, is therefore left behind
/// unless this file names it. The SDK's native crash handler is not compiled in (it would
/// send memory dumps), no trail of earlier events is kept, nothing is written to disk, and
/// no identifier of the installation or the device goes along.
/// </remarks>
internal sealed partial class ErrorReporter : IDisposable
{
    private const string CheckTag = "check";

    private static readonly TimeSpan FlushTime = TimeSpan.FromSeconds(2);

    private readonly string? _address;
    private readonly AppLog _log;
    private readonly ITransport? _transport;
    private readonly PrivacyFilter _privacy;
    private readonly ErrorReportBudget _budget;
    private readonly Lock _gate = new();
    private IDisposable? _sdk;

    /// <param name="address">Where reports go; null for a build without an address.</param>
    /// <param name="log">The local log.</param>
    /// <param name="privacy">Removes the user's and the computer's name from what the user types as feedback.</param>
    /// <param name="budget">Keeps one bug from being reported over and over.</param>
    /// <param name="transport">For the self-test: receives the reports instead of the network.</param>
    public ErrorReporter(string? address, AppLog log, PrivacyFilter privacy, ErrorReportBudget budget, ITransport? transport = null)
    {
        _address = address;
        _log = log;
        _privacy = privacy;
        _budget = budget;
        _transport = transport;
    }

    /// <summary>
    /// Where this build sends reports; null for a build without an address (a development
    /// build, or one somebody else compiled), which therefore sends nothing.
    /// </summary>
    public static string? CompiledAddress { get; } =
        typeof(ErrorReporter).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .FirstOrDefault(attribute => attribute.Key == ErrorReports.AddressMetadataKey)?.Value is { Length: > 0 } address
            ? address
            : null;

    /// <summary>Whether reports are sent right now, and if not, why.</summary>
    public ErrorReportsState State { get; private set; }

    /// <summary>Starts or stops reporting to match the build, the organisation's policy and what the user has said.</summary>
    public void Apply(ErrorReportsChoice choice, IRegistryProbe registry)
    {
        lock (_gate)
        {
            State = ErrorReports.State(_address, choice, registry);
            if (State == ErrorReportsState.On && _sdk is null)
            {
                try
                {
                    _sdk = SentrySdk.Init(Configure);
                }
#pragma warning disable CA1031 // Reporting errors must never be the reason SecReview does not start.
                catch (Exception exception)
#pragma warning restore CA1031
                {
                    _log.Error("Error reporting could not start", exception);
                    State = ErrorReportsState.NoAddress;
                }
            }
            else if (State != ErrorReportsState.On && _sdk is not null)
            {
                // Switched off: what was waiting is dropped, not sent (the SDK is told not to
                // wait at shutdown).
                _sdk.Dispose();
                _sdk = null;
            }
        }
    }

    /// <summary>Reports an error; <paramref name="checkId"/> names the check it happened in, if any. Never throws.</summary>
    public void Report(Exception exception, string? checkId = null)
    {
        if (_sdk is null || !_budget.Allow(ErrorReports.Fingerprint(exception)))
        {
            return;
        }

        try
        {
            var report = new SentryEvent(exception);
            if (ErrorReports.IsCheckId(checkId))
            {
                report.SetTag(CheckTag, checkId!);
            }

            SentrySdk.CaptureEvent(report);
        }
#pragma warning disable CA1031 // An error while reporting an error is logged, nothing more.
        catch (Exception failure)
#pragma warning restore CA1031
        {
            _log.Error("An error could not be reported", failure);
        }
    }

    /// <summary>Reports that the previous run never closed down. Says nothing else: there is nothing else known.</summary>
    public void ReportAbnormalEnd()
    {
        if (_sdk is not null && _budget.Allow(ErrorReports.AbnormalEndMessage))
        {
            SentrySdk.CaptureMessage(ErrorReports.AbnormalEndMessage, SentryLevel.Warning);
        }
    }

    /// <summary>
    /// Hands what the user wrote, with exactly the text they were shown as included, to the
    /// SDK for sending. Returns false when reporting is not on.
    /// </summary>
    public bool SendFeedback(string text, string? included)
    {
        if (_sdk is null)
        {
            return false;
        }

        string message = ErrorReports.Text(text, _privacy, ErrorReports.MaximumFeedbackLength);
        if (!string.IsNullOrWhiteSpace(included))
        {
            message += Environment.NewLine + Environment.NewLine + included;
        }

        SentrySdk.CaptureFeedback(new SentryFeedback(message));
        return true;
    }

    /// <summary>Sends what is waiting, for a moment at most. For the end of the process.</summary>
    public void Flush()
    {
        if (_sdk is not null)
        {
            SentrySdk.Flush(FlushTime);
        }
    }

    /// <summary>Sends what is waiting, briefly, and stops.</summary>
    public void Dispose()
    {
        lock (_gate)
        {
            if (_sdk is not null)
            {
                SentrySdk.Flush(FlushTime);
                _sdk.Dispose();
                _sdk = null;
            }
        }
    }

    private void Configure(SentryOptions options)
    {
        options.Dsn = _address;
        options.Release = $"secreview@{ProductInfo.Version}";
        options.Environment = "production";

        // Nothing about the person or the PC, no record of what happened before an error, no
        // usage statistics, nothing kept on disk, no performance data.
        options.SendDefaultPii = false;
        options.MaxBreadcrumbs = 0;
        options.AutoSessionTracking = false;
        options.SendClientReports = false;
        options.CacheDirectoryPath = null;
        options.DisableFileWrite = true; // not even the SDK's own "installation" file in the user's profile
        options.ReportAssembliesMode = ReportAssembliesMode.None;
        options.TracesSampleRate = 0;
        options.IsGlobalModeEnabled = true;
        options.AttachStacktrace = false;
        options.ShutdownTimeout = TimeSpan.Zero; // sending at exit is Flush's job; switching off must not send

        // SecReview decides itself what is an error worth reporting (Program, the window and
        // the scanner call Report); the SDK's own hooks would bypass the once-a-day rule.
        options.DisableAppDomainUnhandledExceptionCapture();
        options.DisableUnobservedTaskExceptionCapture();
        options.DisableWinUiUnhandledExceptionIntegration();
        options.DisableDiagnosticSourceIntegration();
        options.DisableSystemDiagnosticsMetricsIntegration();

        options.SetBeforeBreadcrumb(_ => null);
        options.SetBeforeSend((report, _) => Clean(report));
        options.SetBeforeSendFeedback((report, _) => Clean(report));
        if (_transport is not null)
        {
            options.Transport = _transport;
        }
    }

    /// <summary>
    /// The last word on what leaves the PC. Returns a new report holding only what is named
    /// here; null (nothing is sent) when the report has none of it.
    /// </summary>
    private static SentryEvent? Clean(SentryEvent report)
    {
        var clean = new SentryEvent
        {
            Level = report.Level,
            Release = report.Release,
            Environment = report.Environment,
            User = new SentryUser(),
        };

        // An error: its type and where it happened. Never its message, which can quote
        // anything, nor anything attached to it.
        if (report.SentryExceptions is { } errors)
        {
            clean.SentryExceptions = errors.Select(error => new SentryException
            {
                Type = error.Type,
                Module = error.Module,
                Stacktrace = error.Stacktrace is null
                    ? null
                    : new SentryStackTrace { Frames = [.. error.Stacktrace.Frames.Select(CleanFrame)] },
                Mechanism = error.Mechanism is null
                    ? null
                    : new Mechanism
                    {
                        Type = error.Mechanism.Type,
                        Handled = error.Mechanism.Handled,
                        ExceptionId = error.Mechanism.ExceptionId,
                        ParentId = error.Mechanism.ParentId,
                        IsExceptionGroup = error.Mechanism.IsExceptionGroup,
                    },
            }).ToList();
        }

        // The one message SecReview sends, a fixed text. Any other message is not sent.
        string? message = report.Message?.Formatted ?? report.Message?.Message;
        if (message == ErrorReports.AbnormalEndMessage)
        {
            clean.Message = new SentryMessage { Message = ErrorReports.AbnormalEndMessage };
        }

        // Feedback: the text the user approved, nothing else of it.
        if (report.Contexts.Feedback is { Message: { Length: > 0 } feedback })
        {
            clean.Contexts.Feedback = new SentryFeedback(feedback);
        }

        // The versions of Windows and .NET.
        if (report.Contexts.TryGetValue(Sentry.Protocol.OperatingSystem.Type, out object? os) && os is Sentry.Protocol.OperatingSystem system)
        {
            clean.Contexts.OperatingSystem.Name = system.Name;
            clean.Contexts.OperatingSystem.Version = system.Version;
            clean.Contexts.OperatingSystem.Build = system.Build;
            clean.Contexts.OperatingSystem.RawDescription = system.RawDescription;
        }

        if (report.Contexts.TryGetValue(Runtime.Type, out object? net) && net is Runtime runtime)
        {
            clean.Contexts.Runtime.Name = runtime.Name;
            clean.Contexts.Runtime.Version = runtime.Version;
            clean.Contexts.Runtime.RawDescription = runtime.RawDescription;
        }

        // The check the error happened in: an identifier from SecReview's own catalogue.
        if (report.Tags.TryGetValue(CheckTag, out string? check) && ErrorReports.IsCheckId(check))
        {
            clean.SetTag(CheckTag, check);
        }

        bool hasSomething = clean.SentryExceptions is not null || clean.Message is not null || clean.Contexts.Feedback is not null;
        return hasSomething ? clean : null;
    }

    /// <summary>A step of the stack: which method, in which module, at which address. No source paths, no variables.</summary>
    private static SentryStackFrame CleanFrame(SentryStackFrame frame) => new()
    {
        Function = frame.Function,
        Module = frame.Module,
        Package = frame.Package,
        InApp = frame.InApp,
        LineNumber = frame.LineNumber,
        ColumnNumber = frame.ColumnNumber,
        InstructionAddress = frame.InstructionAddress,
        ImageAddress = frame.ImageAddress,
        SymbolAddress = frame.SymbolAddress,
        AddressMode = frame.AddressMode,
    };

    /// <summary>
    /// For the self-test: writes each report to a file as it would have gone over the network,
    /// so the build can read what a report really holds.
    /// </summary>
    internal sealed class FileTransport(string path) : ITransport
    {
        private readonly Lock _gate = new();

        public Task SendEnvelopeAsync(Envelope envelope, CancellationToken cancellationToken = default)
        {
            lock (_gate)
            {
                using var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read);
                envelope.Serialize(stream, null);
                stream.WriteByte((byte)'\n');
            }

            return Task.CompletedTask;
        }
    }
}
