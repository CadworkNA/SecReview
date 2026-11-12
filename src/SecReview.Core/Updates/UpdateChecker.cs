using System.Net;
using System.Net.Http.Headers;

namespace SecReview.Updates;

/// <summary>Fetches one file for the update check. The real one is <see cref="HttpUpdateTransport"/>.</summary>
public interface IUpdateTransport
{
    /// <summary>
    /// The file's bytes. Throws <see cref="UpdateTransportException"/> with words fit to show
    /// when it cannot be fetched, is larger than <paramref name="maximumBytes"/>, or the
    /// server sends SecReview somewhere it does not go.
    /// </summary>
    Task<byte[]> GetAsync(Uri url, int maximumBytes, CancellationToken cancellation);
}

/// <summary>A fetch that failed, with a reason fit to show.</summary>
public sealed class UpdateTransportException : Exception
{
    public UpdateTransportException()
    {
    }

    public UpdateTransportException(string message)
        : base(message)
    {
    }

    public UpdateTransportException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// Looks whether there is a newer SecReview. It asks one question of one compiled-in address,
/// without saying anything about this PC, and installs nothing.
/// </summary>
public sealed class UpdateChecker
{
    private readonly UpdateSource _source;
    private readonly IUpdateTransport _transport;
    private readonly TimeProvider _clock;
    private readonly string _installed;

    /// <param name="source">Where this build looks.</param>
    /// <param name="transport">How the file is fetched.</param>
    /// <param name="clock">The time.</param>
    /// <param name="installed">The version that is running.</param>
    public UpdateChecker(UpdateSource source, IUpdateTransport transport, TimeProvider clock, string installed)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(clock);
        ArgumentException.ThrowIfNullOrWhiteSpace(installed);
        _source = source;
        _transport = transport;
        _clock = clock;
        _installed = installed;
    }

    /// <summary>
    /// Looks once and says what was found. Never throws: a look that fails is an outcome,
    /// with its reason, and never reads as "up to date".
    /// </summary>
    public async Task<UpdateState> CheckAsync(CancellationToken cancellation = default)
    {
        DateTimeOffset now = _clock.GetUtcNow();
        var state = new UpdateState { CheckedAt = now, CheckedBy = _installed };
        if (_source.ManifestUrl is not { } url)
        {
            return state with { Outcome = UpdateOutcome.Failed, Problem = "This build of SecReview does not look for updates." };
        }

        (UpdateManifest? manifest, string? problem) = await FetchAsync(url, cancellation).ConfigureAwait(false);
        if (manifest is null)
        {
            return state with { Outcome = UpdateOutcome.Failed, Problem = problem };
        }

        return UpdateRules.IsNewer(manifest.Version, _installed)
            ? state with { Outcome = UpdateOutcome.Available, Available = manifest.Version, Published = manifest.Published, Notes = manifest.Notes }
            : state with { Outcome = UpdateOutcome.UpToDate };
    }

    /// <summary>The manifest as it is on the server right now, or the reason there is none.</summary>
    public async Task<(UpdateManifest? Manifest, string? Problem)> FetchAsync(CancellationToken cancellation = default) =>
        _source.ManifestUrl is { } url
            ? await FetchAsync(url, cancellation).ConfigureAwait(false)
            : (null, "This build of SecReview does not look for updates.");

    private async Task<(UpdateManifest? Manifest, string? Problem)> FetchAsync(Uri url, CancellationToken cancellation)
    {
        byte[] bytes;
        try
        {
            bytes = await _transport.GetAsync(url, UpdateManifest.MaximumBytes, cancellation).ConfigureAwait(false);
        }
        catch (UpdateTransportException exception)
        {
            return (null, $"Could not look for updates: {exception.Message}.");
        }
        catch (OperationCanceledException) when (!cancellation.IsCancellationRequested)
        {
            return (null, "Could not look for updates: the server took too long to answer.");
        }

        UpdateManifest? manifest = UpdateManifest.Parse(bytes, _source, _clock.GetUtcNow(), out string? problem);
        return manifest is null ? (null, $"Could not look for updates: {problem}.") : (manifest, null);
    }
}

/// <summary>
/// Fetches over HTTPS, and only from where the build allows. No cookies, no sign-in, no
/// identifier: the request carries the product's name and version and nothing else. A server
/// may send SecReview on to another address (GitHub does, for release files); each such
/// address is checked like the first, and there are few of them.
/// </summary>
public sealed class HttpUpdateTransport : IUpdateTransport, IDisposable
{
    private const int MaximumRedirects = 5;

    private readonly UpdateSource _source;
    private readonly HttpClient _client;

    /// <param name="source">Which addresses are allowed.</param>
    /// <param name="handler">For tests; the real one is made here.</param>
    /// <param name="timeout">How long one request may take.</param>
    public HttpUpdateTransport(UpdateSource source, HttpMessageHandler? handler = null, TimeSpan? timeout = null)
    {
        ArgumentNullException.ThrowIfNull(source);
        _source = source;
        _client = new HttpClient(handler ?? new SocketsHttpHandler
        {
            // Followed by hand, so every address is checked before it is asked.
            AllowAutoRedirect = false,
            UseCookies = false,
            PreAuthenticate = false,
            Credentials = null,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = TimeSpan.FromSeconds(15),
        })
        {
            Timeout = timeout ?? TimeSpan.FromSeconds(30),
        };
        _client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue(ProductInfo.Name, ProductInfo.Version.Replace('+', '.')));
    }

    public Task<byte[]> GetAsync(Uri url, int maximumBytes, CancellationToken cancellation) =>
        ReadAsync(url, maximumBytes, destination: null, progress: null, cancellation);

    /// <summary>
    /// Fetches a file into a stream (the setup program, into a file). Throws
    /// <see cref="UpdateTransportException"/> like <see cref="GetAsync"/>.
    /// </summary>
    /// <param name="url">The address.</param>
    /// <param name="maximumBytes">More than this is not written.</param>
    /// <param name="destination">Where the bytes go.</param>
    /// <param name="progress">Told how many bytes have arrived and how many are expected (0 when the server does not say).</param>
    /// <param name="cancellation">Abandons the fetch.</param>
    public async Task DownloadAsync(Uri url, long maximumBytes, Stream destination, Action<long, long>? progress, CancellationToken cancellation)
    {
        ArgumentNullException.ThrowIfNull(destination);
        await ReadAsync(url, maximumBytes, destination, progress, cancellation).ConfigureAwait(false);
    }

    private async Task<byte[]> ReadAsync(Uri url, long maximumBytes, Stream? destination, Action<long, long>? progress, CancellationToken cancellation)
    {
        ArgumentNullException.ThrowIfNull(url);
        Uri current = url;
        for (int hop = 0; hop <= MaximumRedirects; hop++)
        {
            if (!_source.Allows(current))
            {
                throw new UpdateTransportException(hop == 0
                    ? "the address is not one this build fetches from"
                    : "the server sent SecReview on to an address it does not fetch from");
            }

            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, current);
                using HttpResponseMessage response = await _client
                    .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellation)
                    .ConfigureAwait(false);

                if ((int)response.StatusCode is 301 or 302 or 303 or 307 or 308)
                {
                    if (response.Headers.Location is not { } location)
                    {
                        throw new UpdateTransportException("the server sent SecReview on without saying where");
                    }

                    current = location.IsAbsoluteUri ? location : new Uri(current, location);
                    continue;
                }

                if (!response.IsSuccessStatusCode)
                {
                    throw new UpdateTransportException($"the server answered {(int)response.StatusCode}");
                }

                long expected = response.Content.Headers.ContentLength ?? 0;
                if (expected > maximumBytes)
                {
                    throw new UpdateTransportException("the file is larger than it can be");
                }

                await using Stream body = await response.Content.ReadAsStreamAsync(cancellation).ConfigureAwait(false);
                using var memory = destination is null ? new MemoryStream() : null;
                Stream target = destination ?? memory!;
                byte[] buffer = new byte[81920];
                long total = 0;
                int read;
                while ((read = await body.ReadAsync(buffer, cancellation).ConfigureAwait(false)) > 0)
                {
                    total += read;
                    if (total > maximumBytes)
                    {
                        throw new UpdateTransportException("the file is larger than it can be");
                    }

                    await target.WriteAsync(buffer.AsMemory(0, read), cancellation).ConfigureAwait(false);
                    progress?.Invoke(total, expected);
                }

                return memory?.ToArray() ?? [];
            }
            catch (HttpRequestException exception)
            {
                // The kind of failure, never the exception's own text: that can name a proxy or an address.
                throw new UpdateTransportException(exception.HttpRequestError switch
                {
                    HttpRequestError.NameResolutionError => "the server's name could not be found (no network?)",
                    HttpRequestError.ConnectionError => "the server could not be reached",
                    HttpRequestError.SecureConnectionError => "the secure connection could not be set up",
                    _ => "the request failed",
                }, exception);
            }
            catch (IOException exception)
            {
                throw new UpdateTransportException("the connection broke off", exception);
            }
        }

        throw new UpdateTransportException("the server sent SecReview from address to address too many times");
    }

    public void Dispose() => _client.Dispose();
}
