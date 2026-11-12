using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using SecReview.Probing.Windows;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.Security;
using Windows.Win32.Security.WinTrust;
using Windows.Win32.System.Threading;

namespace SecReview.Updates.Windows;

/// <summary>The parts of installing an update that are Windows' own.</summary>
/// <param name="checkRevocation">
/// Whether Windows also asks whether the signing certificates were revoked (it does for a
/// real update; tests look at files without going to the network).
/// </param>
[SupportedOSPlatform(MinimumWindows.Platform)]
public sealed unsafe class WindowsUpdateHost(bool checkRevocation = true) : IUpdateHost
{
    /// <summary>The folder next to SecReview's own, in Program Files, that downloads go into.</summary>
    public const string WorkFolderName = "SecReview.Update";

    /// <summary>"Verify a file's Authenticode signature": WINTRUST_ACTION_GENERIC_VERIFY_V2.</summary>
    private static readonly Guid VerifyAction = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    public bool IsElevated => WindowsProbes.IsProcessElevated();

    /// <summary>
    /// A new folder under Program Files, which ordinary users cannot write to, with a name
    /// nobody can guess and permissions of its own: SYSTEM and Administrators, nobody else,
    /// nothing inherited. What earlier updates left there is removed first.
    /// </summary>
    public string CreateWorkFolder()
    {
        string parent = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), WorkFolderName);
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (WellKnownSidType who in (WellKnownSidType[])[WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid])
        {
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(who, null),
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        }

        var parentFolder = new DirectoryInfo(parent);
        if (parentFolder.Exists)
        {
            // Not a link somebody put there, and nothing of an earlier update left in it.
            if (parentFolder.LinkTarget is not null || (parentFolder.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new IOException("The folder for updates is not an ordinary folder.");
            }

            // Whoever made it, from now on it is SYSTEM's and administrators' only.
            parentFolder.SetAccessControl(security);

            foreach (FileSystemInfo old in parentFolder.EnumerateFileSystemInfos())
            {
                try
                {
                    if (old is DirectoryInfo folder && (old.Attributes & FileAttributes.ReparsePoint) == 0)
                    {
                        folder.Delete(recursive: true);
                    }
                    else
                    {
                        old.Delete();
                    }
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                    // Still in use (an update that is running): left for next time.
                }
            }
        }
        else
        {
            parentFolder.Create(security);
        }

        var work = new DirectoryInfo(Path.Combine(parent, Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16))));
        work.Create(security);
        return work.FullName;
    }

    public InstallerSignature Inspect(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        fixed (char* file = path)
        {
            var fileInfo = new WINTRUST_FILE_INFO { cbStruct = (uint)sizeof(WINTRUST_FILE_INFO), pcwszFilePath = file };
            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)sizeof(WINTRUST_DATA),
                dwUIChoice = WINTRUST_DATA_UICHOICE.WTD_UI_NONE,
                fdwRevocationChecks = checkRevocation ? WINTRUST_DATA_REVOCATION_CHECKS.WTD_REVOKE_WHOLECHAIN : WINTRUST_DATA_REVOCATION_CHECKS.WTD_REVOKE_NONE,
                dwUnionChoice = WINTRUST_DATA_UNION_CHOICE.WTD_CHOICE_FILE,
                dwStateAction = WINTRUST_DATA_STATE_ACTION.WTD_STATEACTION_VERIFY,
                dwProvFlags = checkRevocation
                    ? WINTRUST_DATA_PROVIDER_FLAGS.WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
                    : WINTRUST_DATA_PROVIDER_FLAGS.WTD_CACHE_ONLY_URL_RETRIEVAL,
            };
            data.Anonymous.pFile = &fileInfo;

            Guid action = VerifyAction;
            HWND noWindow = new((nint)(-1)); // "no user interface, ever"
            int result = PInvoke.WinVerifyTrust(noWindow, &action, &data);
            try
            {
                if (result != 0)
                {
                    return Invalid($"Windows answered 0x{result:X8}");
                }

                CRYPT_PROVIDER_DATA* provider = PInvoke.WTHelperProvDataFromStateData(data.hWVTStateData);
                CRYPT_PROVIDER_SGNR* signer = provider is null ? null : PInvoke.WTHelperGetProvSignerFromChain(provider, 0, false, 0);
                CRYPT_PROVIDER_CERT* signerCertificate = signer is null ? null : PInvoke.WTHelperGetProvCertFromChain(signer, 0);
                if (signerCertificate is null || signerCertificate->pCert is null || signer->csCertChain == 0)
                {
                    return Invalid("Windows does not say who signed it");
                }

                // The far end of the chain Windows built and accepted: the root.
                CRYPT_PROVIDER_CERT* rootCertificate = PInvoke.WTHelperGetProvCertFromChain(signer, signer->csCertChain - 1);
                if (rootCertificate is null || rootCertificate->pCert is null)
                {
                    return Invalid("Windows does not say which root the signature chains to");
                }

                using var root = new X509Certificate2((nint)rootCertificate->pCert);
                string rootHash = root.GetCertHashString(HashAlgorithmName.SHA256);

                // Read only now that the file is known to be unchanged since it was signed:
                // the version information is part of what the signature covers.
                FileVersionInfo info = FileVersionInfo.GetVersionInfo(path);
                string version = info.FileVersion is null ? string.Empty : $"{info.FileMajorPart}.{info.FileMinorPart}.{info.FileBuildPart}.{info.FilePrivatePart}";
                string product = info.ProductVersion?.Trim() ?? string.Empty;

                // A copy of the certificate Windows just verified; freed with the object.
                using var certificate = new X509Certificate2((nint)signerCertificate->pCert);
                string[] usages =
                [
                    .. certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>()
                        .SelectMany(extension => extension.EnhancedKeyUsages.Cast<Oid>())
                        .Select(oid => oid.Value ?? string.Empty),
                ];

                // A timestamp shows as a counter-signature on the signer.
                return new InstallerSignature(true, signer->csCounterSigners > 0, certificate.Subject, usages, rootHash, version, product);
            }
            finally
            {
                // Frees what the verification kept; its answer no longer matters.
                data.dwStateAction = WINTRUST_DATA_STATE_ACTION.WTD_STATEACTION_CLOSE;
                _ = PInvoke.WinVerifyTrust(noWindow, &action, &data);
            }
        }
    }

    private static InstallerSignature Invalid(string problem) => new(false, false, string.Empty, [], string.Empty, string.Empty, string.Empty, problem);

    public void Start(string path, IReadOnlyList<string> arguments)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(arguments);
        var start = new ProcessStartInfo(path)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = Environment.SystemDirectory,
        };

        // Setup unpacks itself into the temporary folder before it runs. Inherited from the
        // user who asked, that would be a folder the user can write to; this one only
        // administrators can.
        string temporary = Path.GetDirectoryName(Path.GetFullPath(path))!;
        start.Environment["TEMP"] = temporary;
        start.Environment["TMP"] = temporary;
        foreach (string argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using Process? started = Process.Start(start);
        if (started is null)
        {
            throw new IOException("Windows did not start the setup program.");
        }
    }

    public bool CallerIsSameUser(NamedPipeClientStream pipe)
    {
        ArgumentNullException.ThrowIfNull(pipe);
        bool held = false;
        try
        {
            pipe.SafePipeHandle.DangerousAddRef(ref held);
            if (!PInvoke.GetNamedPipeServerProcessId(new HANDLE(pipe.SafePipeHandle.DangerousGetHandle()), out uint processId))
            {
                return false;
            }

            HANDLE process = PInvoke.OpenProcess(PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_LIMITED_INFORMATION, false, processId);
            if (process.IsNull)
            {
                return false;
            }

            try
            {
                HANDLE token;
                if (!PInvoke.OpenProcessToken(process, TOKEN_ACCESS_MASK.TOKEN_QUERY, &token))
                {
                    return false;
                }

                using var tokenHandle = new SafeAccessTokenHandle(token);
                using var caller = new WindowsIdentity(tokenHandle.DangerousGetHandle());
                using WindowsIdentity me = WindowsIdentity.GetCurrent();
                return caller.User is not null && caller.User == me.User;
            }
            finally
            {
                PInvoke.CloseHandle(process);
            }
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or System.Security.SecurityException or ArgumentException)
        {
            return false;
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
