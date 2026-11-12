namespace SecReview.Probing;

public enum ServiceStartType
{
    /// <summary>Started with Windows (including drivers started at boot).</summary>
    Automatic,

    /// <summary>Started when something asks for it.</summary>
    Manual,

    /// <summary>Cannot be started.</summary>
    Disabled,
}

/// <summary>A Windows service as the Service Control Manager reports it.</summary>
public sealed record ServiceInfo(string Name, ServiceStartType StartType, bool IsRunning);

public interface IServiceProbe
{
    /// <summary><see cref="ProbeStatus.NotFound"/> when no service of that name is installed.</summary>
    ProbeResult<ServiceInfo> GetService(string name);
}
