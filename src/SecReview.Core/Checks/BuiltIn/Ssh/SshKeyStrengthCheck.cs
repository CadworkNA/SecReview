using SecReview.Probing;

namespace SecReview.Checks.BuiltIn.Ssh;

/// <summary>
/// SSH keys must use an algorithm and size that are still considered safe: Ed25519, ECDSA, a
/// hardware security key, or RSA of at least <see cref="MinimumRsaBits"/> bits. DSA fails at
/// any size: current OpenSSH no longer accepts it.
/// </summary>
public sealed class SshKeyStrengthCheck : ICheck
{
    public const string Id = "ssh.keys.strength";

    /// <summary>Below this an RSA key is no longer considered safe.</summary>
    public const int MinimumRsaBits = 2048;

    private const string Expected = "Ed25519, ECDSA or RSA 2048+";

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.Access, Severity.Low, AdminNeed.No, CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        ProbeResult<IReadOnlyList<SshKeyOnDisk>> found = SshKeys.Find(context.Probes);
        if (!found.IsOk)
        {
            return ProbeOutcomes.FromFailure(found, "your SSH keys");
        }

        IReadOnlyList<SshKeyOnDisk> keys = found.Value!;
        if (keys.Count == 0)
        {
            return CheckOutcome.NotApplicable("No SSH private keys in your .ssh folder.");
        }

        var findings = new List<Finding>(keys.Count);
        var weak = new List<string>();
        var unknown = new List<string>();
        foreach (SshKeyOnDisk key in keys)
        {
            if (key.Info is null)
            {
                unknown.Add(key.FileName);
                findings.Add(Finding.Problem(key.FileName, key.Unreadable ?? "Could not be read", Expected));
                continue;
            }

            string description = SshKeys.Describe(key.Info);
            switch (Judge(key.Info))
            {
                case true:
                    findings.Add(Finding.Ok(key.FileName, description, Expected));
                    break;
                case false:
                    weak.Add(key.FileName);
                    findings.Add(Finding.Problem(key.FileName, description, Expected));
                    break;
                default:
                    unknown.Add(key.FileName);
                    findings.Add(Finding.Problem(
                        key.FileName, key.Info.Kind == SshKeyKind.Rsa ? "RSA, size not readable" : "Kind not readable", Expected));
                    break;
            }
        }

        if (weak.Count > 0)
        {
            return CheckOutcome.Fail(
                $"{Wording.JoinWithAnd(weak)} {(weak.Count == 1 ? "uses" : "use")} a weak algorithm or key size.", findings);
        }

        if (unknown.Count > 0)
        {
            // An encrypted key without its .pub file does not show what it is.
            return CheckOutcome.Error(
                $"Could not tell what kind of key {Wording.JoinWithAnd(unknown)} {Wording.IsOrAre(unknown.Count)}; " +
                "the matching .pub file is missing.",
                findings);
        }

        return CheckOutcome.Pass(
            keys.Count == 1 ? "Your SSH key is strong enough." : $"All {keys.Count} SSH keys are strong enough.", findings);
    }

    /// <summary>True for strong, false for weak, null when the file does not show enough to say.</summary>
    private static bool? Judge(SshKeyInfo info) => info.Kind switch
    {
        SshKeyKind.Ed25519 or SshKeyKind.Ecdsa or SshKeyKind.SecurityKey => true,
        SshKeyKind.Dsa => false,
        SshKeyKind.Rsa => info.Bits is { } bits ? bits >= MinimumRsaBits : null,
        _ => null,
    };
}
