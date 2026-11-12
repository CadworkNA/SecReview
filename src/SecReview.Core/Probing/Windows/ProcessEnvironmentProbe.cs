namespace SecReview.Probing.Windows;

/// <summary>Known folders, environment variables and uptime, as this process sees them.</summary>
public sealed class ProcessEnvironmentProbe : IEnvironmentProbe
{
    public ProbeResult<string> Folder(KnownFolder folder)
    {
        Environment.SpecialFolder? special = folder switch
        {
            KnownFolder.UserProfile => Environment.SpecialFolder.UserProfile,
            KnownFolder.RoamingAppData => Environment.SpecialFolder.ApplicationData,
            KnownFolder.LocalAppData => Environment.SpecialFolder.LocalApplicationData,
            KnownFolder.ProgramData => Environment.SpecialFolder.CommonApplicationData,
            KnownFolder.ProgramFiles => Environment.SpecialFolder.ProgramFiles,
            KnownFolder.ProgramFilesX86 => Environment.SpecialFolder.ProgramFilesX86,
            KnownFolder.Windows => Environment.SpecialFolder.Windows,
            _ => null,
        };

        if (special is null)
        {
            return ProbeFailure.Failed($"Unknown folder: {folder}.");
        }

        // Asked for as it is, without creating the folder when it does not exist.
        string path = Environment.GetFolderPath(special.Value, Environment.SpecialFolderOption.DoNotVerify);
        return string.IsNullOrEmpty(path) ? ProbeFailure.NotFound() : ProbeResult<string>.Ok(path);
    }

    public string? Variable(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        string? value = Environment.GetEnvironmentVariable(name);
        return string.IsNullOrEmpty(value) ? null : value;
    }

    public ProbeResult<TimeSpan> Uptime() => ProbeResult<TimeSpan>.Ok(TimeSpan.FromMilliseconds(Environment.TickCount64));
}
