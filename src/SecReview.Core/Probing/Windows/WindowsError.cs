using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;

namespace SecReview.Probing.Windows;

/// <summary>Turns Windows error codes and exceptions into <see cref="ProbeFailure"/>s.</summary>
internal static class WindowsError
{
    private const int ErrorFileNotFound = 2;
    private const int ErrorPathNotFound = 3;
    private const int ErrorAccessDenied = 5;
    private const int ErrorPrivilegeNotHeld = 1314;
    private const int EAccessDenied = unchecked((int)0x80070005);
    private const int ClassNotRegistered = unchecked((int)0x80040154);
    private const int ENoInterface = unchecked((int)0x80004002);

    /// <summary>HRESULTs of the form 0x8007xxxx wrap a Win32 error code in their low word.</summary>
    private const int Win32FacilityMask = unchecked((int)0xFFFF0000);
    private const int Win32Facility = unchecked((int)0x80070000);

    /// <summary>A failure for a Win32 error code (as returned by an API or GetLastError).</summary>
    public static ProbeFailure FromWin32(int error, string what) => error switch
    {
        ErrorAccessDenied or ErrorPrivilegeNotHeld => ProbeFailure.AccessDenied(),
        ErrorFileNotFound or ErrorPathNotFound => ProbeFailure.NotFound(),
        _ => ProbeFailure.Failed(Describe(what, error)),
    };

    /// <summary>A failure for an HRESULT returned by a COM or Windows API call.</summary>
    public static ProbeFailure FromHResult(int hresult, string what)
    {
        if ((hresult & Win32FacilityMask) == Win32Facility)
        {
            // The same condition gets the same status whichever style of API reported it.
            ProbeFailure failure = FromWin32(hresult & 0xFFFF, what);
            return failure.Status == ProbeStatus.Failed ? ProbeFailure.Failed(Describe(what, hresult)) : failure;
        }

        return hresult switch
        {
            EAccessDenied => ProbeFailure.AccessDenied(),
            ClassNotRegistered or ENoInterface =>
                ProbeFailure.NotSupported($"{what} is not available on this edition of Windows."),
            _ => ProbeFailure.Failed(Describe(what, hresult)),
        };
    }

    /// <summary>
    /// A failure for an exception thrown while reading; never lets one escape a probe. Only
    /// exceptions that carry a Windows result code are interpreted. Anything else is a defect
    /// in the probe and is reported as a failure with its message: several ordinary .NET
    /// exceptions share their code with a COM result (InvalidCastException is E_NOINTERFACE)
    /// and must not be mistaken for "not supported".
    /// </summary>
    public static ProbeFailure FromException(Exception exception, string what) => exception switch
    {
        // The runtime turns the common failure codes of a Windows call into these types.
        UnauthorizedAccessException or System.Security.SecurityException => ProbeFailure.AccessDenied(),
        FileNotFoundException or DirectoryNotFoundException => ProbeFailure.NotFound(),
        COMException com => FromHResult(com.HResult, what),
        Win32Exception win32 => FromWin32(win32.NativeErrorCode, what),
        _ => ProbeFailure.Failed($"{what} failed: {exception.GetType().Name}: {exception.Message}"),
    };

    private static string Describe(string what, int code)
    {
        string message = Marshal.GetPInvokeErrorMessage(code).Trim();
        string number = string.Create(CultureInfo.InvariantCulture, $"0x{code:X8}");
        return message.Length == 0 || message.StartsWith("Unknown error", StringComparison.Ordinal)
            ? $"{what} failed ({number})."
            : $"{what} failed: {message} ({number})";
    }
}
