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
/// organisation allows it and the user has left it on.
/// </summary>
/// <remarks>
/// Every report passes through <see cref="Clean"/> on its way out, whatever raised it: names
/// are removed from texts, the message of an error inside a check is dropped, and everything
/// the SDK adds about the device beyond the versions of Windows and .NET is taken off. The
/// SDK's native crash handler is not compiled in (it would send memory dumps), no trail of
/// earlier events is kept, nothing is written to disk, and no identifier of the installation
/// or the device goes along (the SDK would otherwise make one up and keep it in a file).
/// </remarks>
internal sealed partial class ErrorReporter : IDisposable
{
    private const string CheckTag = "check";

    private static readonly TimeSpan FlushTime = TimeSpan.FromSeconds(2);

    /// <summary>What the SDK may say about where it runs. Everything else it gathers is removed.</summary>
    private static readonly string[] KeptContexts = ["os", "runtime", "app", "trace", "feedback"];

    private readonly string? _address;
    private readonly AppLog _log;
    private readonly ITransport? _transport;
    private readonly PrivacyFilter _privacy;
    private readonly ErrorReportBudget _budget = new();
    private readonly Lock _gate = new();
    private IDisposable? _sdk;

    /// <param name="address">Where reports go; null for a build without an address.</param>
    /// <param name="log">The local log.</param>
    /// <param name="privacy">Removes the user's and the computer's name from texts.</param>
    /// <param name="transport">For the self-test: receives the reports instead of the network.</param>
    public ErrorReporter(string? address, AppLog log, PrivacyFilter privacy, ITransport? transport = null)
    {
        _address = address;
        _log = log;
        _privacy = privacy;
        _transport = transport;
    }

    /// <summary>Whether reports are sent right now, and if not, why.</summary>
    public ErrorReportsState State { get; private set; }

    /// <summary>Starts or stops reporting to match the build, the organisation's policy and the user's switch.</summary>
    public void Apply(bool settingOn, IRegistryProbe registry)
    {
        lock (_gate)
        {
            State = ErrorReports.State(_address, settingOn, registry);
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
                _sdk.Dispose();
                _sdk = null;
            }
        }
    }

    /// <summary>Reports an error; <paramref name="checkId"/> names the check it happened in, if any. Never throws.</summary>
    public void Report(Exception exception, string? checkId = null)
    {
        if (_sdk is null || !_budget.Allow(ErrorReports.Fingerprint(exception, checkId)))
        {
            return;
        }

        try
        {
            var report = new SentryEvent(exception);
            if (checkId is not null)
            {
                report.SetTag(CheckTag, checkId);
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
        if (_sdk is not null && _budget.Allow("previous run ended abnormally"))
        {
            SentrySdk.CaptureMessage("The previous run of SecReview ended without closing down.", SentryLevel.Warning);
        }
    }

    /// <summary>
    /// Sends what the user wrote, with what they chose to include. Returns false when nothing
    /// was sent because reporting is not on.
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
            message += Environment.NewLine + Environment.NewLine + _privacy.Scrub(included);
        }

        SentrySdk.CaptureFeedback(new SentryFeedback(message));
        return true;
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
        options.AttachStacktrace = true;

        // SecReview decides itself what is an error worth reporting (Program and the scanner
        // call Report); the SDK's own hooks would bypass the once-per-error rule.
        options.DisableAppDomainUnhandledExceptionCapture();
        options.DisableUnobservedTaskExceptionCapture();

        options.SetBeforeBreadcrumb(_ => null);
        options.SetBeforeSend((report, _) => Clean(report));
        options.SetBeforeSendFeedback((report, _) => Clean(report));
        if (_transport is not null)
        {
            options.Transport = _transport;
        }
    }

    /// <summary>The last word on what leaves the PC: every report goes through here.</summary>
    private SentryEvent Clean(SentryEvent report)
    {
        bool fromCheck = report.Tags.ContainsKey(CheckTag);

        report.ServerName = null;
        report.User = new SentryUser();
        if (report.Message is { } message)
        {
            report.Message = new SentryMessage { Message = ErrorReports.Text(message.Formatted ?? message.Message, _privacy, ErrorReports.MaximumMessageLength) };
        }

        foreach (SentryException error in report.SentryExceptions ?? [])
        {
            // The message of an error inside a check can quote what the check was reading.
            error.Value = fromCheck ? null : ErrorReports.Text(error.Value, _privacy, ErrorReports.MaximumMessageLength);
            error.Mechanism?.Data.Clear();
            foreach (SentryStackFrame frame in error.Stacktrace?.Frames ?? [])
            {
                frame.AbsolutePath = frame.AbsolutePath is null ? null : _privacy.Scrub(frame.AbsolutePath);
                frame.FileName = frame.FileName is null ? null : _privacy.Scrub(frame.FileName);
                frame.ContextLine = null;
                frame.Vars.Clear();
            }
        }

        foreach (string context in report.Contexts.Keys.Where(key => !KeptContexts.Contains(key)).ToArray())
        {
            report.Contexts.Remove(context);
        }

        return report;
    }

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
