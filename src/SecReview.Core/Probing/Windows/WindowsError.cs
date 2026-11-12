using System.Globalization;
using System.Runtime.InteropServices;

namespace SecReview.Probing.Windows;

/// <summary>Turns Windows error codes and exceptions into <see cref="ProbeFailure"/>s.</summary>
internal static class WindowsError
{
    private const int ErrorFileNotFound = 2;
    private const int ErrorAccessDenied = 5;
    private const int ErrorPrivilegeNotHeld = 1314;
    private const int EAccessDenied = unchecked((int)0x80070005);
    private const int EPrivilegeNotHeld = unchecked((int)0x80070522);
    private const int ClassNotRegistered = unchecked((int)0x80040154);
    private const int ENoInterface = unchecked((int)0x80004002);

    /// <summary>A failure for a Win32 error code (as returned by an API or GetLastError).</summary>
    public static ProbeFailure FromWin32(int error, string what) => error switch
    {
        ErrorAccessDenied or ErrorPrivilegeNotHeld => ProbeFailure.AccessDenied(),
        ErrorFileNotFound => ProbeFailure.NotFound(),
        _ => ProbeFailure.Failed(Describe(what, error)),
    };

    /// <summary>A failure for an HRESULT.</summary>
    public static ProbeFailure FromHResult(int hresult, string what) => hresult switch
    {
        EAccessDenied or EPrivilegeNotHeld => ProbeFailure.AccessDenied(),
        ClassNotRegistered or ENoInterface =>
            ProbeFailure.NotSupported($"{what} is not available on this edition of Windows."),
        _ => ProbeFailure.Failed(Describe(what, hresult)),
    };

    /// <summary>A failure for an exception thrown while reading; never lets one escape a probe.</summary>
    public static ProbeFailure FromException(Exception exception, string what) => exception switch
    {
        UnauthorizedAccessException or System.Security.SecurityException => ProbeFailure.AccessDenied(),
        _ => FromHResult(exception.HResult, what),
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
