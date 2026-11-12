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
/// The pipe is the first of its name, takes one connection at a time, and can be written to
/// by Administrators only: the helper always is one once Windows has started it elevated,
/// whichever account answered the prompt, and nothing that runs without those rights can
/// connect in its place. Not even the user who made the pipe may change who is allowed, and
/// nothing comes in over the network. On top of that, only a connection from the very
/// process Windows started for us is listened to; any other is hung up on. What arrives is
/// read like a results file: size-capped, every field checked, and only results for
/// administrator checks of this version are taken, read with administrator rights.
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
    public static Task<AdministratorScanResult> RunAsync(
        IElevatedLauncher launcher, IReadOnlyList<ICheck> checks, CheckTexts texts, TimeSpan? timeout = null, CancellationToken cancellation = default) =>
        RunAsync(launcher, checks, texts, timeout, alsoThisUser: false, cancellation);

    /// <summary>
    /// As above. <paramref name="alsoThisUser"/> opens the pipe to the current user as well:
    /// for tests only, which play the helper from an ordinary process.
    /// </summary>
    internal static async Task<AdministratorScanResult> RunAsync(
        IElevatedLauncher launcher, IReadOnlyList<ICheck> checks, CheckTexts texts, TimeSpan? timeout, bool alsoThisUser, CancellationToken cancellation = default)
    {
        ArgumentNullException.ThrowIfNull(launcher);
        ArgumentNullException.ThrowIfNull(checks);
        ArgumentNullException.ThrowIfNull(texts);

        ICheck[] expected = [.. checks.Where(check => CheckRunner.IsIncluded(check.Definition, CheckSelection.AdministratorOnly))];
        string name = ElevationPipe.NewName();
        try
        {
            using NamedPipeServerStream pipe = CreatePipe(name, alsoThisUser);

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

            // An answer read without administrator rights is not what was asked for.
            if (!scan.Elevated || scan.Checks.Any(check => !check.Result.Elevated))
            {
                return Failed("The administrator checks ran without administrator rights; their answer was not used.");
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

    /// <summary>The pipe: the first of its name, one connection at a time, for this PC's administrators only.</summary>
    internal static NamedPipeServerStream CreatePipe(string name, bool alsoThisUser)
    {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));

        // The maker of a pipe owns it, and an owner may normally rewrite who is allowed. This
        // entry takes that away: the owner may look at the list, not change it.
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.WinCreatorOwnerRightsSid, null), PipeAccessRights.ReadPermissions, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));

        if (alsoThisUser)
        {
            using WindowsIdentity me = WindowsIdentity.GetCurrent();
            security.AddAccessRule(new PipeAccessRule(me.User!, PipeAccessRights.ReadWrite, AccessControlType.Allow));
        }

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
        await WaitForHelperAsync(pipe, helperProcessId, cancellation).ConfigureAwait(false);

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

    /// <summary>
    /// Waits until the helper itself has connected. A connection from any other process is
    /// hung up on and the wait goes on.
    /// </summary>
    internal static async Task WaitForHelperAsync(NamedPipeServerStream pipe, int helperProcessId, CancellationToken cancellation)
    {
        while (true)
        {
            try
            {
                await pipe.WaitForConnectionAsync(cancellation).ConfigureAwait(false);
                if (ClientProcessId(pipe) == helperProcessId)
                {
                    return;
                }
            }
            catch (IOException)
            {
                // Something connected and left again before it was looked at. Not the helper,
                // which stays until it has written its answer; the wait goes on.
            }

            pipe.Disconnect();
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
/// <param name="helperPath">The helper's full path.</param>
/// <param name="command">What the helper is asked to do: one of the two things it does with administrator rights.</param>
public sealed class WindowsElevatedLauncher(string helperPath, string command = WindowsElevatedLauncher.ScanCommand) : IElevatedLauncher
{
    public const string ScanCommand = "--elevated-scan";
    public const string UpdateCommand = "--apply-update";

    /// <summary>Windows' code for "the user cancelled".</summary>
    private const int Cancelled = 1223;

    public ElevatedProcess? Start(string pipeName)
    {
        if (!ElevationPipe.IsValidName(pipeName) || !Path.IsPathFullyQualified(helperPath) || command is not (ScanCommand or UpdateCommand))
        {
            throw new InvalidOperationException("The helper cannot be started with that.");
        }

        var start = new ProcessStartInfo(helperPath)
        {
            UseShellExecute = true,
            Verb = "runas",
            Arguments = $"{command} --pipe {pipeName}",
            WindowStyle = ProcessWindowStyle.Hidden,

            // Not the folder the app happened to be started in, which a user may be able to write to.
            WorkingDirectory = Environment.SystemDirectory,
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
