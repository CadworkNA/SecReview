using System.ComponentModel;
using System.IO.Pipes;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using SecReview.Elevation;

namespace SecReview.Updates;

/// <summary>
/// Who signs SecReview's releases, compiled into the programs by the release workflow. An
/// update is only installed when its setup program is signed by exactly this publisher. A
/// build without it (a developer's, a fork's, an unsigned one) never installs an update.
/// </summary>
/// <param name="Subject">The signing certificate's subject, as Windows writes it.</param>
/// <param name="IdentityOid">
/// The identifier the signing service puts into every certificate of this publisher (an
/// "enhanced key usage" that stays the same while the certificates themselves change every
/// few days); empty when the publisher's certificates have none.
/// </param>
/// <param name="RootSha256">
/// The SHA-256 of the root certificate the publisher's certificates chain to. Without it,
/// "signed by this publisher" would mean "by anyone with a certificate of that name under any
/// root this PC or this user trusts", and a user's own trusted roots can be added to without
/// administrator rights.
/// </param>
public sealed record PublisherIdentity(string Subject, string IdentityOid, string RootSha256)
{
    public const string SubjectKey = "PublisherSubject";
    public const string IdentityKey = "PublisherIdentityOid";
    public const string RootKey = "PublisherRootSha256";

    /// <summary>The publisher compiled into this build.</summary>
    public static PublisherIdentity Compiled { get; } = new(Metadata(SubjectKey), Metadata(IdentityKey), Metadata(RootKey));

    /// <summary>Whether this build names a publisher: the subject and the root, both.</summary>
    public bool IsConfigured => Subject.Length > 0 && RootSha256.Length == 64;

    private static string Metadata(string key) =>
        typeof(PublisherIdentity).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>().FirstOrDefault(a => a.Key == key)?.Value?.Trim() ?? string.Empty;
}

/// <summary>What Windows says about a downloaded setup program.</summary>
/// <param name="Valid">Windows accepts its signature: unchanged since signing, chained to a root this PC trusts, not revoked.</param>
/// <param name="Timestamped">The signature carries the time it was made, so it outlives its certificate.</param>
/// <param name="Subject">The signer's subject.</param>
/// <param name="KeyUsages">The signer certificate's enhanced key usages.</param>
/// <param name="RootSha256">The SHA-256 of the root certificate the signer's chain ends in, as Windows built it.</param>
/// <param name="FileVersion">The version in the file's own version information ("1.4.0.0"); empty when it has none.</param>
/// <param name="ProductVersion">The product version in the same information ("1.4.0" or "1.4.0-rc.1"): the version in full.</param>
/// <param name="Problem">Why it is not valid, in words fit to show; null when it is.</param>
public sealed record InstallerSignature(
    bool Valid, bool Timestamped, string Subject, IReadOnlyList<string> KeyUsages, string RootSha256, string FileVersion, string ProductVersion, string? Problem = null);

/// <summary>The parts of installing an update that touch Windows; the rules are in <see cref="UpdateApplier"/>.</summary>
public interface IUpdateHost
{
    /// <summary>Whether this process has administrator rights.</summary>
    bool IsElevated { get; }

    /// <summary>A new, empty folder that only administrators can read or write.</summary>
    string CreateWorkFolder();

    /// <summary>What Windows says about a file's signature.</summary>
    InstallerSignature Inspect(string path);

    /// <summary>Starts a program with arguments, without a shell.</summary>
    void Start(string path, IReadOnlyList<string> arguments);

    /// <summary>
    /// Whether the process at the other end of the pipe (the window that asked) runs as the
    /// same user as this one. False when Windows does not say.
    /// </summary>
    bool CallerIsSameUser(NamedPipeClientStream pipe);
}

/// <summary>Fetches the setup program; <see cref="HttpUpdateTransport"/> does both.</summary>
public interface IUpdateDownloader : IUpdateTransport
{
    Task DownloadAsync(Uri url, long maximumBytes, Stream destination, Action<long, long>? progress, CancellationToken cancellation);
}

/// <summary>Where installing an update stands; one line of the pipe each.</summary>
public enum UpdateStage
{
    /// <summary>Asking the server again which version is the newest.</summary>
    Checking = 1,
    Downloading,
    Verifying,

    /// <summary>The setup program has been started. SecReview is closed by it and opens again when it is done.</summary>
    Installing,

    /// <summary>Nothing was installed; <see cref="UpdateProgress.Problem"/> says why.</summary>
    Failed,
}

/// <summary>One step of installing an update, as the helper reports it.</summary>
public sealed record UpdateProgress(UpdateStage Stage, long Done = 0, long Total = 0, string? Problem = null)
{
    /// <summary>The longest line the helper sends or the window reads.</summary>
    public const int MaximumLineLength = 600;

    public string ToLine() => string.Create(
        System.Globalization.CultureInfo.InvariantCulture, $"{(int)Stage}|{Done}|{Total}|{Problem?.ReplaceLineEndings(" ")}");

    /// <summary>A line read back; null when it is not one of ours.</summary>
    public static UpdateProgress? FromLine(string? line)
    {
        if (line is null || line.Length > MaximumLineLength)
        {
            return null;
        }

        string[] parts = line.Split('|', 4);
        if (parts.Length != 4 ||
            !int.TryParse(parts[0], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int stage) ||
            !Enum.IsDefined((UpdateStage)stage) ||
            !long.TryParse(parts[1], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out long done) ||
            !long.TryParse(parts[2], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out long total))
        {
            return null;
        }

        // Shown in the window: plain text only.
        string problem = new([.. parts[3].Where(c => !char.IsControl(c))]);
        return new UpdateProgress((UpdateStage)stage, done, total, problem.Length > 0 ? problem : null);
    }
}

/// <summary>
/// What the helper does when started with <c>--apply-update --pipe name</c>, with administrator
/// rights. It takes nothing from whoever started it but the pipe to report on: which version,
/// from where, and whether to trust it, it finds out itself.
///
/// An update is installed only when all of this holds: the build has an update address and a
/// publisher compiled in; the organisation allows it; the server's newest version is higher
/// than the one running; the downloaded file has the SHA-256 the server names; Windows
/// accepts its signature, which is timestamped; it is signed by the compiled-in publisher,
/// under the compiled-in root; and the file's own version is exactly that higher version.
/// Anything else ends with a reason and nothing installed.
/// </summary>
public static class UpdateApplier
{
    /// <summary>A setup program larger than this is not SecReview's.</summary>
    public const long MaximumSetupBytes = 300L * 1024 * 1024;

    /// <summary>The helper lives this long at most: it is an elevated process.</summary>
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(15);

    /// <summary>Set for setup: open SecReview again when done (see installer\SecReview.iss).</summary>
    public const string RelaunchArgument = "/RELAUNCH=1";

    private static readonly string[] SilentArguments = ["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"];

    /// <param name="pipeName">The pipe to report on.</param>
    /// <param name="source">Where this build looks for updates.</param>
    /// <param name="publisher">Who signs its releases.</param>
    /// <param name="policy">What the organisation decided.</param>
    /// <param name="installed">The running version.</param>
    /// <param name="downloader">Fetches the manifest and the setup program.</param>
    /// <param name="host">The parts that touch Windows.</param>
    /// <param name="clock">The time.</param>
    /// <param name="cancellation">Abandons the run.</param>
    /// <returns>Whether the setup program was started.</returns>
    public static async Task<bool> RunAsync(
        string pipeName,
        UpdateSource source,
        PublisherIdentity publisher,
        UpdatePolicy policy,
        string installed,
        IUpdateDownloader downloader,
        IUpdateHost host,
        TimeProvider clock,
        CancellationToken cancellation = default)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(publisher);
        ArgumentNullException.ThrowIfNull(downloader);
        ArgumentNullException.ThrowIfNull(host);
        ArgumentNullException.ThrowIfNull(clock);
        if (!ElevationPipe.IsValidName(pipeName))
        {
            return false;
        }

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        deadline.CancelAfter(Lifetime);
        cancellation = deadline.Token;

        try
        {
            // As for the administrator checks: this PC only, write only, and whoever made the
            // pipe can never act in this process's name.
            using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.Out, PipeOptions.Asynchronous, TokenImpersonationLevel.Anonymous);
            await pipe.ConnectAsync(ElevatedHelper.ConnectTimeout, cancellation).ConfigureAwait(false);

            async Task Say(UpdateProgress progress)
            {
                await pipe.WriteAsync(Encoding.UTF8.GetBytes(progress.ToLine() + "\n"), cancellation).ConfigureAwait(false);
                await pipe.FlushAsync(cancellation).ConfigureAwait(false);
            }

            try
            {
                string? problem = await ApplyAsync(pipe, Say, source, publisher, policy, installed, downloader, host, clock, cancellation).ConfigureAwait(false);
                if (problem is null)
                {
                    return true;
                }

                await Say(new UpdateProgress(UpdateStage.Failed, Problem: problem)).ConfigureAwait(false);
                return false;
            }
            catch (UpdateTransportException exception)
            {
                await Say(new UpdateProgress(UpdateStage.Failed, Problem: $"The update could not be downloaded: {exception.Message}.")).ConfigureAwait(false);
                return false;
            }
        }
        catch (Exception exception) when (exception is IOException or TimeoutException or UnauthorizedAccessException or OperationCanceledException or Win32Exception)
        {
            // The pipe is gone or time is up: nobody is left to tell, and nothing was installed.
            return false;
        }
    }

    /// <summary>Null when the setup program was started; otherwise why nothing was installed.</summary>
    private static async Task<string?> ApplyAsync(
        NamedPipeClientStream pipe,
        Func<UpdateProgress, Task> say,
        UpdateSource source,
        PublisherIdentity publisher,
        UpdatePolicy policy,
        string installed,
        IUpdateDownloader downloader,
        IUpdateHost host,
        TimeProvider clock,
        CancellationToken cancellation)
    {
        if (!source.IsConfigured || !publisher.IsConfigured)
        {
            return "This build of SecReview does not install updates.";
        }

        if (policy.NoUpdateCheck || policy.NoSelfUpdate)
        {
            return "Your organisation installs SecReview's updates itself.";
        }

        if (!host.IsElevated)
        {
            return "Installing an update needs administrator rights.";
        }

        await say(new UpdateProgress(UpdateStage.Checking)).ConfigureAwait(false);
        (UpdateManifest? manifest, string? fetchProblem) =
            await new UpdateChecker(source, downloader, clock, installed).FetchAsync(cancellation).ConfigureAwait(false);
        if (manifest is null)
        {
            return fetchProblem;
        }

        if (!UpdateRules.IsNewer(manifest.Version, installed))
        {
            return $"SecReview {installed} is the newest version already.";
        }

        // Into a folder only administrators can touch, under a fixed name: nothing the server
        // says takes part in where the file goes.
        string folder = host.CreateWorkFolder();
        string setup = Path.Combine(folder, SetupFileName);
        string? refused = await DownloadAndCheckAsync(setup, manifest, say, publisher, installed, downloader, host, pipe, cancellation).ConfigureAwait(false);
        if (refused is not null)
        {
            // What was not installed does not stay on the PC.
            try
            {
                File.Delete(setup);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                // Removed with the folder at the next update.
            }
        }

        return refused;
    }

    /// <summary>The name the downloaded setup program is saved under.</summary>
    public const string SetupFileName = "SecReview-setup.exe";

    private static async Task<string?> DownloadAndCheckAsync(
        string setup,
        UpdateManifest manifest,
        Func<UpdateProgress, Task> say,
        PublisherIdentity publisher,
        string installed,
        IUpdateDownloader downloader,
        IUpdateHost host,
        NamedPipeClientStream pipe,
        CancellationToken cancellation)
    {
        await using (var file = new FileStream(setup, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            long lastSaid = -1;
            await downloader.DownloadAsync(
                manifest.Url,
                MaximumSetupBytes,
                file,
                (done, total) =>
                {
                    // Every 2 MB is often enough for a progress bar. Not awaited: progress is a courtesy.
                    if (done - lastSaid >= 2 * 1024 * 1024)
                    {
                        lastSaid = done;
                        _ = say(new UpdateProgress(UpdateStage.Downloading, done, total));
                    }
                },
                cancellation).ConfigureAwait(false);
            await file.FlushAsync(cancellation).ConfigureAwait(false);
        }

        await say(new UpdateProgress(UpdateStage.Verifying)).ConfigureAwait(false);

        // Held open, for reading only, from here until the program has been started: nobody
        // can change or replace the file between checking it and running it.
        await using var held = new FileStream(setup, FileMode.Open, FileAccess.Read, FileShare.Read);
        string hash = Convert.ToHexStringLower(await SHA256.HashDataAsync(held, cancellation).ConfigureAwait(false));
        if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(hash), Encoding.ASCII.GetBytes(manifest.Sha256)))
        {
            return "The downloaded update is not the file the server announced. Nothing was installed.";
        }

        if (Refusal(host.Inspect(setup), publisher, manifest.Version, installed) is { } refusal)
        {
            return refusal;
        }

        // SecReview is opened again by setup only for the user who asked; where another
        // account's administrator rights were used, that user opens it again themselves.
        string[] arguments = host.CallerIsSameUser(pipe) ? [.. SilentArguments, RelaunchArgument] : SilentArguments;
        await say(new UpdateProgress(UpdateStage.Installing)).ConfigureAwait(false);
        host.Start(setup, arguments);
        return null;
    }

    /// <summary>
    /// Why a setup program is not installed; null when it may be. The signature is Windows'
    /// to judge; who signed it and what version it is are SecReview's.
    /// </summary>
    public static string? Refusal(InstallerSignature signature, PublisherIdentity publisher, string offered, string installed)
    {
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(publisher);
        const string Nothing = " Nothing was installed.";

        if (!publisher.IsConfigured)
        {
            return "This build of SecReview does not install updates.";
        }

        if (!signature.Valid)
        {
            return $"The downloaded update is not validly signed{(signature.Problem is null ? string.Empty : $" ({signature.Problem})")}.{Nothing}";
        }

        if (!signature.Timestamped)
        {
            return $"The downloaded update's signature has no timestamp.{Nothing}";
        }

        if (!string.Equals(signature.Subject, publisher.Subject, StringComparison.Ordinal) ||
            !string.Equals(signature.RootSha256, publisher.RootSha256, StringComparison.OrdinalIgnoreCase) ||
            (publisher.IdentityOid.Length > 0 && !signature.KeyUsages.Contains(publisher.IdentityOid, StringComparer.Ordinal)))
        {
            return $"The downloaded update is not signed by SecReview's publisher.{Nothing}";
        }

        // The file's own version, which the signature covers: exactly the announced one, and
        // higher than what runs. A signed but older setup program must not be installed over
        // a newer SecReview, and a signed pre-release must not pass for the release.
        string numbers = offered.Split('-', 2)[0];
        if (signature.ProductVersion != offered || signature.FileVersion != numbers + ".0" || !UpdateRules.IsNewer(offered, installed))
        {
            return $"The downloaded update is not the announced version.{Nothing}";
        }

        return null;
    }
}

/// <summary>How installing an update from the window ended.</summary>
public enum UpdateInstallOutcome
{
    /// <summary>The setup program is running; SecReview is about to be closed by it.</summary>
    Installing,

    /// <summary>The user said no at the Windows prompt. Nothing happened.</summary>
    Cancelled,

    /// <summary>Nothing was installed; the problem says why.</summary>
    Failed,
}

/// <summary>
/// The window's side of installing an update: make the private pipe, start the helper through
/// the Windows prompt, and pass on what it reports. The same pipe rules as for the
/// administrator checks: administrators only, the first of its name, and only the process
/// Windows started is heard.
/// </summary>
public static class UpdateInstall
{
    /// <summary>The helper's argument for this.</summary>
    public const string Command = WindowsElevatedLauncher.UpdateCommand;

    private const int MaximumBytes = 64 * 1024;

    /// <summary>How long the window waits for the helper to connect once Windows has started it.</summary>
    internal static TimeSpan ConnectTimeout { get; set; } = TimeSpan.FromSeconds(30);

    public static Task<(UpdateInstallOutcome Outcome, string? Problem)> RunAsync(
        IElevatedLauncher launcher, Action<UpdateProgress> onProgress, CancellationToken cancellation = default) =>
        RunAsync(launcher, onProgress, alsoThisUser: false, cancellation);

    internal static async Task<(UpdateInstallOutcome Outcome, string? Problem)> RunAsync(
        IElevatedLauncher launcher, Action<UpdateProgress> onProgress, bool alsoThisUser, CancellationToken cancellation = default)
    {
        ArgumentNullException.ThrowIfNull(launcher);
        ArgumentNullException.ThrowIfNull(onProgress);

        string name = ElevationPipe.NewName();
        try
        {
            using NamedPipeServerStream pipe = AdministratorScan.CreatePipe(name, alsoThisUser);
            using ElevatedProcess? helper = await Task.Run(() => launcher.Start(name), cancellation).ConfigureAwait(false);
            if (helper is null)
            {
                return (UpdateInstallOutcome.Cancelled, null);
            }

            // The helper connects as soon as it starts; one that has not after half a minute
            // never will (it could not start, or was ended).
            using (var connect = CancellationTokenSource.CreateLinkedTokenSource(cancellation))
            {
                connect.CancelAfter(ConnectTimeout);
                try
                {
                    await AdministratorScan.WaitForHelperAsync(pipe, helper.ProcessId, connect.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!cancellation.IsCancellationRequested)
                {
                    return (UpdateInstallOutcome.Failed, "The update helper did not start. Nothing was installed.");
                }
            }

            using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
            limit.CancelAfter(UpdateApplier.Lifetime + TimeSpan.FromSeconds(30));

            UpdateProgress? last = null;
            long total = 0;
            using var reader = new StreamReader(pipe, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, bufferSize: 1024, leaveOpen: true);
            char[] buffer = new char[UpdateProgress.MaximumLineLength + 1];
            var line = new StringBuilder();
            while (true)
            {
                int read = await reader.ReadAsync(buffer.AsMemory(), limit.Token).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                total += read;
                if (total > MaximumBytes)
                {
                    return (UpdateInstallOutcome.Failed, "The update helper sent more than it should.");
                }

                foreach (char c in buffer.AsSpan(0, read))
                {
                    if (c != '\n')
                    {
                        if (line.Length <= UpdateProgress.MaximumLineLength)
                        {
                            line.Append(c);
                        }

                        continue;
                    }

                    if (UpdateProgress.FromLine(line.ToString()) is { } progress)
                    {
                        last = progress;
                        onProgress(progress);
                    }

                    line.Clear();
                }
            }

            return last switch
            {
                { Stage: UpdateStage.Installing } => (UpdateInstallOutcome.Installing, null),
                { Stage: UpdateStage.Failed } => (UpdateInstallOutcome.Failed, last.Problem ?? "The update could not be installed."),
                _ => (UpdateInstallOutcome.Failed, "The update helper stopped before it was done. Nothing was installed."),
            };
        }
        catch (OperationCanceledException) when (!cancellation.IsCancellationRequested)
        {
            return (UpdateInstallOutcome.Failed, "The update took too long. Nothing was installed.");
        }
        catch (OperationCanceledException)
        {
            return (UpdateInstallOutcome.Cancelled, null);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException or Win32Exception)
        {
            return (UpdateInstallOutcome.Failed, "The update could not be started.");
        }
    }
}
