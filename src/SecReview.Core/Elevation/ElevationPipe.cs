using System.IO.Pipes;
using System.Security.Cryptography;
using System.Security.Principal;
using SecReview.Checks;
using SecReview.Probing;
using SecReview.Scanning;

namespace SecReview.Elevation;

/// <summary>
/// The private pipe the administrator helper answers on. The window makes the pipe under a
/// name nobody can guess and starts the helper with that name; the helper connects, writes the
/// results of the administrator checks as one document and exits. The name is the only thing
/// the helper takes from whoever started it.
/// </summary>
public static class ElevationPipe
{
    /// <summary>How every pipe name begins.</summary>
    public const string Prefix = "SecReview.Elev.";

    /// <summary>The most a results document may hold. More is not read.</summary>
    public const int MaximumBytes = 1024 * 1024;

    private const int RandomHexLength = 32;

    private static readonly System.Buffers.SearchValues<char> LowerHex = System.Buffers.SearchValues.Create("0123456789abcdef");

    /// <summary>A new name: the prefix and 128 random bits.</summary>
    public static string NewName() => Prefix + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(RandomHexLength / 2));

    /// <summary>
    /// Whether a text is a pipe name of exactly this form: the prefix, then 32 lower-case
    /// hexadecimal digits. Anything else (a path, a server name, another pipe) is refused.
    /// </summary>
    public static bool IsValidName(string? name) =>
        name is not null &&
        name.Length == Prefix.Length + RandomHexLength &&
        name.StartsWith(Prefix, StringComparison.Ordinal) &&
        name.AsSpan(Prefix.Length).IndexOfAnyExcept(LowerHex) < 0;
}

/// <summary>
/// What the helper does when started with <c>--elevated-scan --pipe name</c>: run the checks
/// that need administrator rights and send their results down the pipe. It reads nothing from
/// the pipe and takes no other input, so there is nothing to steer it with.
/// </summary>
public static class ElevatedHelper
{
    /// <summary>How long the helper waits for the pipe to be there.</summary>
    public static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(10);

    /// <summary>How long the helper lives at most: it is an elevated process, and nobody may keep one waiting.</summary>
    public static readonly TimeSpan Lifetime = TimeSpan.FromSeconds(100);

    /// <summary>
    /// Runs the administrator checks and writes their results to the pipe. Returns false when
    /// the name is not a pipe name of ours or the pipe could not be reached or written.
    /// </summary>
    /// <param name="pipeName">The pipe to answer on.</param>
    /// <param name="probes">How the PC is read.</param>
    /// <param name="isElevated">Whether this process has administrator rights.</param>
    /// <param name="clock">The clock.</param>
    /// <param name="checks">This version's checks.</param>
    /// <param name="texts">Their wording.</param>
    /// <param name="connectTimeout">How long to wait for the pipe; <see cref="ConnectTimeout"/> if null.</param>
    /// <param name="cancellation">Abandons the run.</param>
    public static async Task<bool> RunAsync(
        string pipeName,
        SystemProbes probes,
        bool isElevated,
        TimeProvider clock,
        IReadOnlyList<ICheck> checks,
        Catalogue.CheckTexts texts,
        TimeSpan? connectTimeout = null,
        CancellationToken cancellation = default)
    {
        ArgumentNullException.ThrowIfNull(probes);
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
            // This PC only, write only. "Anonymous": whoever made the pipe learns nothing
            // about this process's account and can never act in its name. Without it, the
            // maker of a pipe may impersonate whoever connects, and this process may be an
            // administrator.
            using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.Out, PipeOptions.Asynchronous, TokenImpersonationLevel.Anonymous);
            await pipe.ConnectAsync(connectTimeout ?? ConnectTimeout, cancellation).ConfigureAwait(false);

            ScanResult scan = await new Scanner(probes, clock, checks, texts)
                .RunAsync(CheckSelection.AdministratorOnly, isElevated, cancellation)
                .ConfigureAwait(false);

            byte[] document = ResultsStore.ToBytes(scan);
            if (document.Length > ElevationPipe.MaximumBytes)
            {
                return false;
            }

            await pipe.WriteAsync(document, cancellation).ConfigureAwait(false);
            await pipe.FlushAsync(cancellation).ConfigureAwait(false);
            return true;
        }
        catch (Exception exception) when (exception is IOException or TimeoutException or UnauthorizedAccessException or OperationCanceledException)
        {
            return false;
        }
    }
}
