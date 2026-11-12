namespace SecReview.Probing.Windows;

/// <summary>Reads the dates the Windows Update agent hands out.</summary>
internal static class WindowsUpdateDates
{
    /// <summary>
    /// A UTC date from its automation form. The automation "zero date" (1899-12-30) is how the
    /// agent says "never", and gives null.
    /// </summary>
    /// <exception cref="ArgumentException">The number is not a valid automation date.</exception>
    public static DateTimeOffset? FromAutomationDate(double automationDate) => automationDate == 0
        ? null
        : new DateTimeOffset(DateTime.FromOADate(automationDate), TimeSpan.Zero);
}
