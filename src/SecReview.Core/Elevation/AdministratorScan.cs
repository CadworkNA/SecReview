using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using SecReview.Catalogue;
using SecReview.Checks;
using SecReview.Scanning;
using Windows.Win32;

namespace SecReview.Elevation;

/// <summary>How a run of the administrator checks ended.</summary>
public enum AdministratorScanOutcome
{
    /// <summary>Something went wrong; the problem says what. The zero value on purpose.</summary>
    Failed = 0,

    /// <summary>The checks ran and their results are there.</summary>
    Completed,

    /// <summary>The user said no at the Windows prompt. Not an error: the checks simply stay unanswered.</summary>
    Cancelled,
}

/// <summary>What a run of the administrator checks gave.</summary>
/// <param name="Outcome">How it ended.</param>
/// <param name="Scan">The results of the administrator checks; null unless completed.</param>
/// <param name="Problem">What went wrong, in words fit for the window; null unless failed.</param>
public sealed record AdministratorScanResult(AdministratorScanOutcome Outcome, ScanResult? Scan = null, string? Problem = null);

/// <summary>A helper process that was started with administrator rights.</summary>
/// <param name="ProcessId">Its process number, held valid for as long as this object lives.</param>
/// <param name="Handle">What keeps the number from being given to another process; disposed with this object.</param>
public sealed record ElevatedProcess(int ProcessId, IDisposable? Handle = null) : IDisposable
{
    public void Dispose() => Handle?.Dispose();
}

/// <summary>Starts the administrator helper (a fake in tests).</summary>
public interface IElevatedLauncher
{
    /// <summary>
    /// Asks Windows to start the helper with administrator rights, telling it the pipe to
    /// answer on. Returns null when the user declined at the prompt.
    /// </summary>
    /// <exception cref="InvalidOperationException">The helper could not be started for another reason.</exception>
    ElevatedProcess? Start(string pipeName);
}

/// <summary>
/// The window's side of the administrator checks: make the pipe, start the helper through the
/// Windows prompt, take its answer, and trust nothing about it that was not checked.
/// </summary>
/// <remarks>
/// The pipe is the first of its name, takes one connection at a time, and is open to this
/// user, SYSTEM and Administrators only (a standard user may answer the prompt with another
/// account's credentials; the helper then runs as that administrator), never over the network.
/// Only a connection from the very process Windows started for us is listened to; any other is
/// hung up on. What arrives is read like a results file: size-capped, every field checked,
/// and only results for administrator checks of this version are taken.
/// </remarks>
public static class AdministratorScan
{
    /// <summary>The helper's file name; it sits beside the app.</summary>
    public const string HelperFileName = "SecReviewCli.exe";

    /// <summary>How long the helper has, once Windows has started it, to connect and answer.</summary>
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(120);

    /// <summary>
    /// Why the administrator checks cannot be run from this copy of SecReview; null when they
    /// can. The helper is started with administrator rights, so it must be a file an ordinary
    /// user cannot replace: SecReview has to be installed under Program Files.
    /// </summary>
    /// <param name="appDirectory">The folder the app runs from.</param>
    /// <param name="protectedFolders">Folders only administrators can write to (Program Files).</param>
    /// <param name="fileExists">Whether a file exists.</param>
    public static string? WhyUnavailable(string appDirectory, IReadOnlyList<string> protectedFolders, Func<string, bool> fileExists)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(appDirectory);
        ArgumentNullException.ThrowIfNull(protectedFolders);
        ArgumentNullException.ThrowIfNull(fileExists);

        string app = Path.GetFullPath(appDirectory).TrimEnd('\\') + "\\";
        bool isProtected = protectedFolders
            .Where(folder => !string.IsNullOrWhiteSpace(folder))
            .Select(folder => Path.GetFullPath(folder).TrimEnd('\\') + "\\")
            .Any(folder => app.Length > folder.Length && app.StartsWith(folder, StringComparison.OrdinalIgnoreCase));
        if (!isProtected)
        {
            return "The administrator checks can be run once SecReview is installed for everyone (in Program Files).";
        }

        return fileExists(app + HelperFileName) ? null : "The administrator checks cannot be run: a part of SecReview is missing. Install it again.";
    }

    /// <summary>
    /// Runs the administrator checks through the helper and returns their results. Never
    /// throws for anything the helper, the user or another program does.
    /// </summary>
    /// <param name="launcher">Starts the helper.</param>
    /// <param name="checks">This version's checks; only those that need administrator rights are expected back.</param>
    /// <param name="texts">The wording of the checks.</param>
    /// <param name="timeout">How long the helper has to answer once started; <see cref="DefaultTimeout"/> if null.</param>
    /// <param name="cancellation">Abandons the run.</param>
    public static async Task<AdministratorScanResult> RunAsync(
        IElevatedLauncher launcher, IReadOnlyList<ICheck> checks, CheckTexts texts, TimeSpan? timeout = null, CancellationToken cancellation = default)
    {
        ArgumentNullException.ThrowIfNull(launcher);
        ArgumentNullException.ThrowIfNull(checks);
        ArgumentNullException.ThrowIfNull(texts);

        ICheck[] expected = [.. checks.Where(check => CheckRunner.IsIncluded(check.Definition, CheckSelection.AdministratorOnly))];
        string name = ElevationPipe.NewName();
        try
        {
            using NamedPipeServerStream pipe = CreatePipe(name);

            // The Windows prompt blocks until it is answered: not on the caller's thread.
            using ElevatedProcess? helper = await Task.Run(() => launcher.Start(name), cancellation).ConfigureAwait(false);
            if (helper is null)
            {
                return new AdministratorScanResult(AdministratorScanOutcome.Cancelled);
            }

            using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
            limit.CancelAfter(timeout ?? DefaultTimeout);

            byte[]? document = await ReadFromAsync(pipe, helper.ProcessId, limit.Token).ConfigureAwait(false);
            if (document is null)
            {
                return Failed("The administrator checks sent more than they should; their answer was not used.");
            }

            if (ResultsStore.FromBytes(document, expected, texts) is not { } scan || scan.Checks.Count != expected.Length)
            {
                return Failed("The administrator checks' answer could not be used.");
            }

            return new AdministratorScanResult(AdministratorScanOutcome.Completed, scan);
        }
        catch (OperationCanceledException) when (!cancellation.IsCancellationRequested)
        {
            return Failed("The administrator checks did not answer in time.");
        }
        catch (OperationCanceledException)
        {
            return new AdministratorScanResult(AdministratorScanOutcome.Cancelled);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException or Win32Exception)
        {
            return Failed($"The administrator checks could not be run: {exception.Message}");
        }

        static AdministratorScanResult Failed(string problem) => new(AdministratorScanOutcome.Failed, Problem: problem);
    }

    /// <summary>The pipe: the first of its name, one connection at a time, for this PC's user and administrators only.</summary>
    private static NamedPipeServerStream CreatePipe(string name)
    {
        var security = new PipeSecurity();
        using (WindowsIdentity me = WindowsIdentity.GetCurrent())
        {
            security.AddAccessRule(new PipeAccessRule(me.User!, PipeAccessRights.FullControl, AccessControlType.Allow));
        }

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));

        return NamedPipeServerStreamAcl.Create(
            name,
            PipeDirection.In,
            maxNumberOfServerInstances: 1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance,
            inBufferSize: 0,
            outBufferSize: 0,
            security);
    }

    /// <summary>
    /// Waits for the helper to connect and reads all it sends. A connection from any other
    /// process is hung up on and the wait goes on: only the process Windows started for us is
    /// heard. Returns null when more than the cap arrives.
    /// </summary>
    private static async Task<byte[]?> ReadFromAsync(NamedPipeServerStream pipe, int helperProcessId, CancellationToken cancellation)
    {
        while (true)
        {
            await pipe.WaitForConnectionAsync(cancellation).ConfigureAwait(false);
            if (ClientProcessId(pipe) == helperProcessId)
            {
                break;
            }

            pipe.Disconnect();
        }

        using var received = new MemoryStream();
        byte[] buffer = new byte[64 * 1024];
        while (true)
        {
            int read = await pipe.ReadAsync(buffer, cancellation).ConfigureAwait(false);
            if (read == 0)
            {
                return received.ToArray();
            }

            if (received.Length + read > ElevationPipe.MaximumBytes)
            {
                return null;
            }

            received.Write(buffer, 0, read);
        }
    }

    /// <summary>The process at the other end of the pipe; -1 when Windows does not say.</summary>
    private static int ClientProcessId(NamedPipeServerStream pipe)
    {
        bool held = false;
        try
        {
            pipe.SafePipeHandle.DangerousAddRef(ref held);
            return PInvoke.GetNamedPipeClientProcessId(new Windows.Win32.Foundation.HANDLE(pipe.SafePipeHandle.DangerousGetHandle()), out uint processId)
                ? (int)processId
                : -1;
        }
        finally
        {
            if (held)
            {
                pipe.SafePipeHandle.DangerousRelease();
            }
        }
    }
}

/// <summary>
/// Starts the helper through the Windows prompt ("Do you want to allow this app to make
/// changes?"). The helper is named by its full path; the pipe name is the only argument that
/// varies, and it is checked before use.
/// </summary>
public sealed class WindowsElevatedLauncher(string helperPath) : IElevatedLauncher
{
    /// <summary>Windows' code for "the user cancelled".</summary>
    private const int Cancelled = 1223;

    public ElevatedProcess? Start(string pipeName)
    {
        if (!ElevationPipe.IsValidName(pipeName) || !Path.IsPathFullyQualified(helperPath))
        {
            throw new InvalidOperationException("The helper cannot be started with that.");
        }

        var start = new ProcessStartInfo(helperPath)
        {
            UseShellExecute = true,
            Verb = "runas",
            Arguments = $"--elevated-scan --pipe {pipeName}",
            WindowStyle = ProcessWindowStyle.Hidden,
        };

        try
        {
            Process process = Process.Start(start) ?? throw new InvalidOperationException("Windows did not start the helper.");
            return new ElevatedProcess(process.Id, process);
        }
        catch (Win32Exception exception) when (exception.NativeErrorCode == Cancelled)
        {
            return null;
        }
    }
}
