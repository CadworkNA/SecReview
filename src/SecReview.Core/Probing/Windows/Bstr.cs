using System.Runtime.Versioning;
using Windows.Win32;
using Windows.Win32.Foundation;

namespace SecReview.Probing.Windows;

[SupportedOSPlatform(MinimumWindows.Platform)]
internal static class Bstr
{
    /// <summary>Copies a COM string the callee handed over and frees it.</summary>
    public static string Take(BSTR value)
    {
        try
        {
            return value.ToString() ?? string.Empty;
        }
        finally
        {
            PInvoke.SysFreeString(value);
        }
    }
}
