using SecReview.Probing;

namespace SecReview.Checks.BuiltIn.Ssh;

/// <summary>
/// Every SSH private key file in the user's <c>.ssh</c> folder must be protected by a
/// passphrase. A key on a hardware security key is fine without one: the file is only a handle.
/// Keys held by an agent or password manager are not files and are not looked at.
/// </summary>
public sealed class SshKeyPassphraseCheck : ICheck
{
    public const string Id = "ssh.keys.passphrase";

    private const string Expected = "Passphrase";

    public CheckDefinition Definition { get; } =
        new(Id, CheckCategory.Access, Severity.Medium, AdminNeed.No, CheckScope.User);

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
        var unprotected = new List<string>();
        var unknown = new List<string>();
        foreach (SshKeyOnDisk key in keys)
        {
            if (key.Info is null)
            {
                unknown.Add(key.FileName);
                findings.Add(Finding.Problem(key.FileName, key.Unreadable ?? "Could not be read", Expected));
            }
            else if (key.Info.Kind == SshKeyKind.SecurityKey)
            {
                findings.Add(Finding.Ok(key.FileName, "On a hardware security key", Expected));
            }
            else if (key.Info.HasPassphrase is null)
            {
                unknown.Add(key.FileName);
                findings.Add(Finding.Problem(key.FileName, "Format not recognised", Expected));
            }
            else if (key.Info.HasPassphrase.Value)
            {
                findings.Add(Finding.Ok(key.FileName, "Passphrase", Expected));
            }
            else
            {
                unprotected.Add(key.FileName);
                findings.Add(Finding.Problem(key.FileName, "No passphrase", Expected));
            }
        }

        if (unprotected.Count > 0)
        {
            return CheckOutcome.Fail(
                $"{Wording.JoinWithAnd(unprotected)} {(unprotected.Count == 1 ? "has" : "have")} no passphrase.", findings);
        }

        if (unknown.Count > 0)
        {
            return CheckOutcome.Error(
                $"Could not tell whether {Wording.JoinWithAnd(unknown)} {(unknown.Count == 1 ? "has" : "have")} a passphrase.",
                findings);
        }

        return CheckOutcome.Pass(
            keys.Count == 1 ? "Your SSH key is protected." : $"All {keys.Count} SSH keys are protected.", findings);
    }
}
