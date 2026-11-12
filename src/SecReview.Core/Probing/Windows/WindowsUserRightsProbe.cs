using System.Runtime.Versioning;
using System.Security.Principal;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.Security.Authentication.Identity;

namespace SecReview.Probing.Windows;

/// <summary>Reads user rights assignments from the Local Security Authority.</summary>
[SupportedOSPlatform(MinimumWindows.Platform)]
internal sealed class WindowsUserRightsProbe : IUserRightsProbe
{
    private const string What = "Reading the user rights assignments";

    // POLICY_VIEW_LOCAL_INFORMATION | POLICY_LOOKUP_NAMES
    private const uint PolicyAccess = 0x0001 | 0x0800;

    /// <summary>What the enumeration returns when no account holds the right.</summary>
    private const int ErrorNoMoreItems = 259;

    public unsafe ProbeResult<IReadOnlyList<AccountReference>> GetAccountsWithRight(string right)
    {
        ArgumentException.ThrowIfNullOrEmpty(right);

        LSA_HANDLE policy = default;
        void* buffer = null;
        try
        {
            var attributes = new LSA_OBJECT_ATTRIBUTES { Length = (uint)sizeof(LSA_OBJECT_ATTRIBUTES) };
            NTSTATUS opened = PInvoke.LsaOpenPolicy(null, in attributes, PolicyAccess, out policy);
            if (opened.Value != 0)
            {
                return WindowsError.FromWin32((int)PInvoke.LsaNtStatusToWinError(opened), What);
            }

            NTSTATUS listed;
            uint count;
            fixed (char* name = right)
            {
                var rightName = new LSA_UNICODE_STRING
                {
                    Buffer = name,
                    Length = (ushort)(right.Length * sizeof(char)),
                    MaximumLength = (ushort)(right.Length * sizeof(char)),
                };
                listed = PInvoke.LsaEnumerateAccountsWithUserRight(policy, rightName, out buffer, out count);
            }

            if (listed.Value != 0)
            {
                int error = (int)PInvoke.LsaNtStatusToWinError(listed);
                return error == ErrorNoMoreItems
                    ? ProbeResult<IReadOnlyList<AccountReference>>.Ok([])
                    : WindowsError.FromWin32(error, What);
            }

            var entries = (LSA_ENUMERATION_INFORMATION*)buffer;
            var accounts = new List<AccountReference>((int)count);
            for (uint index = 0; index < count; index++)
            {
                var sid = new SecurityIdentifier((nint)entries[index].Sid.Value);
                accounts.Add(new AccountReference(sid.Value, NameOf(sid)));
            }

            return ProbeResult<IReadOnlyList<AccountReference>>.Ok(accounts);
        }
        catch (Exception exception)
        {
            return WindowsError.FromException(exception, What);
        }
        finally
        {
            if (buffer is not null)
            {
                _ = PInvoke.LsaFreeMemory(buffer);
            }

            if (policy.Value != 0)
            {
                _ = PInvoke.LsaClose(policy);
            }
        }
    }

    /// <summary>
    /// The name of a built-in account or group ("BUILTIN\Administrators", "NT AUTHORITY\SYSTEM").
    /// Only identifiers without a domain part are looked up: those resolve on this PC at once,
    /// while a domain account can make Windows wait on a domain controller that a laptop away
    /// from the office cannot reach. Other accounts are shown by identifier.
    /// </summary>
    private static string? NameOf(SecurityIdentifier sid)
    {
        if (sid.AccountDomainSid is not null)
        {
            return null;
        }

        try
        {
            return sid.Translate(typeof(NTAccount)).Value;
        }
        catch (SystemException)
        {
            // No name on this PC (IdentityNotMappedException), or the lookup itself failed.
            // The identifier is still reported, so nothing is lost.
            return null;
        }
    }
}
