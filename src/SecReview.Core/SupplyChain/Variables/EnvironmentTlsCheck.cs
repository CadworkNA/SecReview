using SecReview.Checks;

namespace SecReview.SupplyChain.Variables;

/// <summary>
/// No permanent environment variable may switch off TLS certificate checks for a whole
/// toolchain (Node.js, Git). Variables that replace or extend the trusted certificate
/// authorities are listed, not failed: a company proxy needs them, and so does someone
/// reading your traffic. Settings of single tools (npm, pip, uv, Go) are in those tools' checks.
/// </summary>
public sealed class EnvironmentTlsCheck : ICheck
{
    public const string Id = "sc.env.tls";

    /// <summary>Variables that name a file or folder of certificate authorities to trust.</summary>
    private static readonly (string Name, string Tool, bool Replaces)[] AuthorityVariables =
    [
        ("SSL_CERT_FILE", "OpenSSL-based tools", true),
        ("SSL_CERT_DIR", "OpenSSL-based tools", true),
        ("REQUESTS_CA_BUNDLE", "Python requests", true),
        ("CURL_CA_BUNDLE", "curl", true),
        ("GIT_SSL_CAINFO", "Git", true),
        ("PIP_CERT", "pip", true),
        ("AWS_CA_BUNDLE", "AWS tools", true),
        ("NODE_EXTRA_CA_CERTS", "Node.js", false),
    ];

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.SupplyChain, Severity.High, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (PersistentVariables.Load(context.Probes, out IReadOnlyList<PersistentVariable> variables) is { } failed)
        {
            return failed;
        }

        var problems = new List<Finding>();

        // Node.js: only "0" switches the checks off.
        if (variables.Find("NODE_TLS_REJECT_UNAUTHORIZED") is { } node && node.Value.Trim() == "0")
        {
            problems.Add(Finding.Problem("Node.js TLS certificate checks", "Off", "On", node.Source));
        }

        // Git: set to anything at all, "false" included, it switches the checks off.
        if (variables.FirstOrDefault(v => v.Is("GIT_SSL_NO_VERIFY")) is { } git)
        {
            problems.Add(Finding.Problem("Git TLS certificate checks", "Off", "On", git.Source));
        }

        var notes = new List<Finding>();
        foreach ((string name, string tool, bool replaces) in AuthorityVariables)
        {
            if (variables.Find(name) is { } authority)
            {
                notes.Add(Finding.Note(
                    $"Certificate authorities for {tool}", replaces ? "Replaced by a file you chose" : "Extended by a file you chose", authority.Source));
            }
        }

        if (problems.Count > 0)
        {
            return CheckOutcome.Fail(
                problems.Count == 1
                    ? $"{problems[0].Item} are switched off by a permanent variable."
                    : "TLS certificate checks are switched off for Node.js and Git by permanent variables.",
                [.. problems, .. notes]);
        }

        if (notes.Count > 0)
        {
            return CheckOutcome.Pass(
                notes.Count == 1
                    ? "No variable switches off TLS checks; 1 changes which certificate authorities are trusted."
                    : $"No variable switches off TLS checks; {notes.Count} change which certificate authorities are trusted.",
                [Finding.Ok("TLS certificate checks", "Not switched off", "On"), .. notes]);
        }

        return CheckOutcome.Pass(
            "No permanent variable weakens TLS certificate checks.",
            Finding.Ok("TLS certificate checks", "Not switched off", "On"),
            Finding.Ok("Certificate authorities", "Not changed by a variable", "Not changed"));
    }
}
