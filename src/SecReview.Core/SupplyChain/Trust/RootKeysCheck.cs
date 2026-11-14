using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SecReview.Checks;
using SecReview.Probing;
using SecReview.SupplyChain.Credentials;

namespace SecReview.SupplyChain.Trust;

/// <summary>
/// A certificate authority this PC trusts must not have its private key on this PC: any
/// program that copies the key can then pose as any website or package registry to it.
/// Debugging proxies and local HTTPS tools set this up. A trusted certificate that is good
/// for one site only (a local development certificate) is listed, not failed. Certificates
/// are named by thumbprint; no key is ever opened.
/// </summary>
public sealed class RootKeysCheck : ICheck
{
    public const string Id = "sc.trust.rootkeys";

    internal const string MachinePersonal = @"SOFTWARE\Microsoft\SystemCertificates\MY\Certificates";
    internal const string UserPersonal = @"Software\Microsoft\SystemCertificates\My\Certificates";
    internal const string UserPersonalFolder = @"Microsoft\SystemCertificates\My\Certificates";

    // Local HTTPS and debugging tools that keep their authority's key as a file beside its
    // certificate. The places were checked against each tool's own source on 2026-11-13.
    // mkcert: CAROOT, else %LOCALAPPDATA%\mkcert.
    internal static readonly LocalAuthorityTool Mkcert = new("mkcert", "rootCA.pem", "rootCA-key.pem");

    // mitmproxy: its confdir, ~\.mitmproxy. mitmproxy-ca.pem holds the certificate and the key.
    internal static readonly LocalAuthorityTool Mitmproxy = new("mitmproxy", "mitmproxy-ca-cert.pem", "mitmproxy-ca.pem");

    // HTTP Toolkit: env-paths' config folder, %APPDATA%\httptoolkit\Config.
    internal static readonly LocalAuthorityTool HttpToolkit = new("HTTP Toolkit", "ca.pem", "ca.key");

    // Caddy: XDG_DATA_HOME\caddy, else %APPDATA%\Caddy; a folder per authority under pki\authorities.
    internal static readonly LocalAuthorityTool Caddy = new("Caddy", "root.crt", "root.key");

    // Smallstep: STEPPATH, else ~\.step. step encrypts a key it makes, but that cannot be told
    // without opening the key, so it is judged like the others.
    internal static readonly LocalAuthorityTool Smallstep = new("Smallstep", @"certs\root_ca.crt", @"secrets\root_ca_key");

    /// <summary>Where Windows keeps the authorities it trusts. Each certificate is a key named after its thumbprint.</summary>
    internal static readonly (RegistryRoot Root, string Key)[] Trusted =
    [
        (RegistryRoot.CurrentUser, RootCertificatesCheck.UserRoots),
        (RegistryRoot.CurrentUser, @"Software\Policies\Microsoft\SystemCertificates\Root\Certificates"),
        (RegistryRoot.LocalMachine, @"SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates"),
        (RegistryRoot.LocalMachine, @"SOFTWARE\Microsoft\SystemCertificates\AuthRoot\Certificates"),
        (RegistryRoot.LocalMachine, @"SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates"),
        (RegistryRoot.LocalMachine, @"SOFTWARE\Microsoft\EnterpriseCertificates\Root\Certificates"),
    ];

    private const string Expected = "Its key kept off this PC";
    private const int Most = 10;

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.Medium, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        SystemProbes probes = context.Probes;
        IRegistryProbe registry = probes.Registry;

        if (CredentialPlaces.Folders(probes, out string profile, out string roaming) is { } failed)
        {
            return failed;
        }

        // Thumbprint to the store it is trusted in; the first store wins.
        var trusted = new SortedDictionary<string, (RegistryRoot Root, string Key)>(StringComparer.Ordinal);
        foreach ((RegistryRoot root, string key) in Trusted)
        {
            if (Thumbprints(registry, root, key, "the certificate authorities this PC trusts", out IReadOnlyList<string> names) is { } unread)
            {
                return unread;
            }

            foreach (string name in names)
            {
                trusted.TryAdd(name, (root, key));
            }
        }

        var problems = new List<Finding>();
        var notes = new List<Finding>();
        string? unreadable = null;

        // The personal stores: a certificate there with a key property has its key on this PC.
        foreach ((RegistryRoot root, string key) in ((RegistryRoot, string)[])[(RegistryRoot.LocalMachine, MachinePersonal), (RegistryRoot.CurrentUser, UserPersonal)])
        {
            if (Thumbprints(registry, root, key, "the personal certificates", out IReadOnlyList<string> names) is { } unread)
            {
                return unread;
            }

            foreach (string thumbprint in names.Where(trusted.ContainsKey))
            {
                string source = $@"{Hive(root)}\{key}";
                ProbeResult<RegistryValue> blob = registry.GetValue(root, $@"{key}\{thumbprint}", "Blob");
                if (!blob.IsOk || blob.Value!.Type != RegistryValueType.Binary || !StoredCertificate.TryRead(blob.Value.Binary.Span, out _, out bool hasKey))
                {
                    unreadable ??= "Could not read a personal certificate that is also a trusted authority.";
                }
                else if (hasKey)
                {
                    Judge(registry, trusted, thumbprint, "with a private key in the personal certificates", source);
                }
            }
        }

        // A user's own personal certificates are files; being there is what can be seen.
        string folder = $@"{roaming}\{UserPersonalFolder}";
        ProbeResult<IReadOnlyList<FileEntry>> files = probes.Files.List(folder);
        if (!files.IsOk && files.Status != ProbeStatus.NotFound)
        {
            return ProbeOutcomes.FromFailure(files, "your personal certificates");
        }

        foreach (FileEntry file in files.IsOk ? files.Value! : [])
        {
            string thumbprint = file.Name.ToUpperInvariant();
            if (!file.IsDirectory && IsThumbprint(thumbprint) && trusted.ContainsKey(thumbprint))
            {
                Judge(registry, trusted, thumbprint, "also in your personal certificates, which hold certificates with their key", folder);
            }
        }

        foreach (string stopped in LocalAuthorities(probes, profile, roaming, trusted, problems))
        {
            unreadable ??= stopped;
        }

        if (problems.Count > 0)
        {
            int count = problems.Count;
            return CheckOutcome.Fail(
                count == 1
                    ? "1 trusted certificate authority has its private key on this PC."
                    : $"{count} trusted certificate authorities have their private key on this PC.",
                [.. Shortened(problems), .. Shortened(notes)]);
        }

        if (unreadable is not null)
        {
            return CheckOutcome.Error(unreadable);
        }

        return CheckOutcome.Pass(
            "No trusted certificate authority has its private key on this PC.",
            [Finding.Ok("Trusted certificate authorities with their key on this PC", "None", "None"), .. Shortened(notes)]);

        void Judge(IRegistryProbe from, SortedDictionary<string, (RegistryRoot Root, string Key)> stores, string thumbprint, string how, string source)
        {
            if (problems.Concat(notes).Any(finding => finding.Found.Contains(thumbprint, StringComparison.Ordinal)))
            {
                return;
            }

            (RegistryRoot root, string key) = stores[thumbprint];
            ProbeResult<RegistryValue> blob = from.GetValue(root, $@"{key}\{thumbprint}", "Blob");
            bool? authority = blob.IsOk && blob.Value!.Type == RegistryValueType.Binary &&
                StoredCertificate.TryRead(blob.Value.Binary.Span, out ReadOnlySpan<byte> certificate, out _)
                    ? StoredCertificate.IsAuthority(certificate)
                    : null;
            switch (authority)
            {
                case true:
                    problems.Add(Finding.Problem("Trusted certificate authority", $"Thumbprint {thumbprint}, {how}", Expected, source));
                    break;
                case false:
                    notes.Add(Finding.Note("Trusted certificate for one site", $"Thumbprint {thumbprint}, {how}", source));
                    break;
                default:
                    unreadable ??= "Could not read a trusted certificate whose key may be on this PC.";
                    break;
            }
        }
    }

    /// <summary>
    /// The authorities of local tools whose key is a file beside the certificate.
    /// A key file is only seen in its folder's list, never opened. Yields why a place could not
    /// be looked at, for each that could not.
    /// </summary>
    private static IEnumerable<string> LocalAuthorities(
        SystemProbes probes, string profile, string roaming, SortedDictionary<string, (RegistryRoot Root, string Key)> trusted, List<Finding> problems)
    {
        if (LocalFolders(probes, profile, roaming, out List<(LocalAuthorityTool Tool, string Folder)> places) is { } unread)
        {
            yield return unread;
        }

        foreach ((LocalAuthorityTool tool, string folder) in places)
        {
            if (LocalAuthority(probes.Files, tool, folder, trusted, problems) is { } stopped)
            {
                yield return stopped;
            }
        }
    }

    /// <summary>Where each tool's authority is. Returns why a place could not be told, if one could not.</summary>
    private static string? LocalFolders(SystemProbes probes, string profile, string roaming, out List<(LocalAuthorityTool Tool, string Folder)> places)
    {
        places = [];
        ProbeResult<string> local = probes.Environment.Folder(KnownFolder.LocalAppData);
        if (!local.IsOk)
        {
            return "Windows did not say where your user folders are.";
        }

        if (CredentialPlaces.Moved(probes, "CAROOT", $@"{local.Value}\mkcert", out string mkcert) is { } unread)
        {
            return unread.Summary;
        }

        if (CredentialPlaces.Moved(probes, "STEPPATH", $@"{profile}\.step", out string step) is { } unreadStep)
        {
            return unreadStep.Summary;
        }

        if (CredentialPlaces.Moved(probes, "XDG_DATA_HOME", string.Empty, out string data) is { } unreadData)
        {
            return unreadData.Summary;
        }

        places.Add((Mkcert, mkcert));
        places.Add((Mitmproxy, $@"{profile}\.mitmproxy"));
        places.Add((HttpToolkit, $@"{roaming}\httptoolkit\Config"));
        places.Add((Smallstep, step));

        string caddy = data.Length > 0 ? $@"{data}\caddy\pki\authorities" : $@"{roaming}\Caddy\pki\authorities";
        ProbeResult<IReadOnlyList<FileEntry>> authorities = probes.Files.List(caddy);
        if (authorities.IsOk)
        {
            places.AddRange(authorities.Value!.Where(entry => entry.IsDirectory && !entry.IsLink).Select(entry => (Caddy, $@"{caddy}\{entry.Name}")));
        }
        else if (authorities.Status != ProbeStatus.NotFound)
        {
            return "Could not read the folder of Caddy's certificate authorities.";
        }

        return null;
    }

    /// <summary>One tool's authority: judged when its key file is there. Returns why it could not be looked at, if so.</summary>
    private static string? LocalAuthority(
        IFileProbe files, LocalAuthorityTool tool, string folder, SortedDictionary<string, (RegistryRoot Root, string Key)> trusted, List<Finding> problems)
    {
        string key = $@"{folder}\{tool.Key}";
        int split = key.LastIndexOf('\\');
        ProbeResult<IReadOnlyList<FileEntry>> entries = files.List(key[..split]);
        if (entries.Status == ProbeStatus.NotFound)
        {
            return null;
        }

        if (!entries.IsOk)
        {
            return $"Could not read the folder of {tool.Name}'s certificate authority.";
        }

        string keyName = key[(split + 1)..];
        if (!entries.Value!.Any(entry => !entry.IsDirectory && entry.Name.Equals(keyName, StringComparison.OrdinalIgnoreCase)))
        {
            return null;
        }

        ProbeResult<string> text = files.ReadText($@"{folder}\{tool.Certificate}");
        if (text.Status == ProbeStatus.NotFound)
        {
            return null;
        }

        if (!text.IsOk || StoredCertificate.ThumbprintOfPem(text.Value!) is not { } thumbprint)
        {
            return $"Could not read {tool.Name}'s certificate, whose key file is beside it.";
        }

        if (trusted.ContainsKey(thumbprint) && !problems.Any(finding => finding.Found.Contains(thumbprint, StringComparison.Ordinal)))
        {
            problems.Add(Finding.Problem(
                "Trusted certificate authority", $"Thumbprint {thumbprint}, with its private key in a file of {tool.Name}", Expected, key));
        }

        return null;
    }

    /// <summary>The certificates of a store, by thumbprint in capitals. A store that is not there is empty.</summary>
    private static CheckOutcome? Thumbprints(IRegistryProbe registry, RegistryRoot root, string key, string what, out IReadOnlyList<string> thumbprints)
    {
        thumbprints = [];
        ProbeResult<IReadOnlyList<string>> names = registry.GetSubKeyNames(root, key);
        if (names.Status == ProbeStatus.NotFound)
        {
            return null;
        }

        if (!names.IsOk)
        {
            return ProbeOutcomes.FromFailure(names, what);
        }

        thumbprints = [.. names.Value!.Select(name => name.ToUpperInvariant()).Where(IsThumbprint)];
        return null;
    }

    private static List<Finding> Shortened(List<Finding> findings)
    {
        if (findings.Count <= Most)
        {
            return findings;
        }

        return [.. findings.Take(Most), Finding.Note("More certificates", $"{findings.Count - Most} more")];
    }

    private static string Hive(RegistryRoot root) => root == RegistryRoot.LocalMachine ? "HKLM" : "HKCU";

    private static bool IsThumbprint(string name) => name.Length == 40 && name.All(char.IsAsciiHexDigit);
}

/// <summary>A local tool's certificate authority: the certificate file and the key file, relative to its folder.</summary>
internal sealed record LocalAuthorityTool(string Name, string Certificate, string Key);

/// <summary>
/// A certificate as Windows keeps it in a store: a run of properties, each a number, a
/// reserved number, a length and that many bytes. One property is the certificate itself.
/// </summary>
internal static class StoredCertificate
{
    /// <summary>The property that names where the private key is (CERT_KEY_PROV_INFO_PROP_ID).</summary>
    internal const uint KeyProperty = 2;

    /// <summary>The property that holds the certificate (CERT_CERT_PROP_ID).</summary>
    internal const uint CertificateProperty = 32;

    private const int Header = 12;

    /// <summary>The certificate inside, and whether a key property is with it. False when the bytes are not a stored certificate.</summary>
    public static bool TryRead(ReadOnlySpan<byte> stored, out ReadOnlySpan<byte> certificate, out bool hasKey)
    {
        certificate = default;
        hasKey = false;
        while (stored.Length >= Header)
        {
            uint property = BinaryPrimitives.ReadUInt32LittleEndian(stored);
            uint length = BinaryPrimitives.ReadUInt32LittleEndian(stored[8..]);
            if (length > stored.Length - Header)
            {
                return false;
            }

            ReadOnlySpan<byte> data = stored.Slice(Header, (int)length);
            if (property == CertificateProperty)
            {
                certificate = data;
            }
            else if (property == KeyProperty)
            {
                hasKey = true;
            }

            stored = stored[(Header + (int)length)..];
        }

        return stored.Length == 0 && certificate.Length > 0;
    }

    /// <summary>
    /// Whether a certificate may sign other certificates; null when it cannot be read. One
    /// that does not say is an authority: Windows accepts a trusted root without the field.
    /// </summary>
    public static bool? IsAuthority(ReadOnlySpan<byte> certificate)
    {
        try
        {
            using X509Certificate2 parsed = X509CertificateLoader.LoadCertificate(certificate);
            return parsed.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault() is not { } basic || basic.CertificateAuthority;
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    /// <summary>The thumbprint, in capitals, of the first certificate in PEM text; null when there is none.</summary>
    public static string? ThumbprintOfPem(string text)
    {
        try
        {
            using X509Certificate2 parsed = X509Certificate2.CreateFromPem(text);
            return parsed.Thumbprint.ToUpperInvariant();
        }
        catch (CryptographicException)
        {
            return null;
        }
    }
}
