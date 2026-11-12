using System.Runtime.CompilerServices;

namespace SecReview.Tests;

/// <summary>
/// The test runner (Microsoft.Testing.Platform) sends usage telemetry unless told not to. This
/// turns it off inside the test process itself, so it holds however the tests are started
/// (build.ps1, dotnet test, the IDE), not only when a script sets the variable.
/// </summary>
internal static class TelemetryOptOut
{
#pragma warning disable CA2255 // This is a test executable, not a library.
    [ModuleInitializer]
#pragma warning restore CA2255
    internal static void Apply()
    {
        Environment.SetEnvironmentVariable("TESTINGPLATFORM_TELEMETRY_OPTOUT", "1");
    }
}
