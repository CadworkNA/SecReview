using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.Versioning;
using SecReview.Elevation;

namespace SecReview.Tests.Elevation;

/// <summary>
/// The administrator pipe, as the window makes it, with clients from two other accounts: a
/// standard user must be refused, and an administrator of another account (whoever answers the
/// Windows prompt) let in. Needs two accounts on the machine, so it runs on GitHub's disposable
/// build machines only, through <c>scripts/test-two-accounts.ps1</c>; anywhere else it says so.
/// </summary>
[TestClass]
[SupportedOSPlatform("windows")]
public sealed class TwoAccountPipeTests
{
    private const string StandardUserVariable = "SECREVIEW_TEST_STANDARD_USER";
    private const string OtherAdministratorVariable = "SECREVIEW_TEST_OTHER_ADMINISTRATOR";
    private const string PasswordVariable = "SECREVIEW_TEST_PASSWORD";

    /// <summary>The client's exit codes: connected and wrote; refused; anything else.</summary>
    private const int Connected = 0;
    private const int Refused = 5;

    [TestMethod]
    [TestCategory("TwoAccounts")]
    public async Task AnotherStandardUserIsRefused_AnAdministratorOfAnotherAccountIsLetIn()
    {
        string? standardUser = Environment.GetEnvironmentVariable(StandardUserVariable);
        string? otherAdministrator = Environment.GetEnvironmentVariable(OtherAdministratorVariable);
        string? password = Environment.GetEnvironmentVariable(PasswordVariable);
        if (standardUser is null && otherAdministrator is null && password is null)
        {
            Assert.Inconclusive("Needs two test accounts; scripts/test-two-accounts.ps1 makes them on GitHub's build machines.");
        }

        Assert.IsFalse(
            string.IsNullOrEmpty(standardUser) || string.IsNullOrEmpty(otherAdministrator) || string.IsNullOrEmpty(password),
            "All three test account variables must be set.");

        string name = ElevationPipe.NewName();
        using NamedPipeServerStream pipe = AdministratorScan.CreatePipe(name, alsoThisUser: false);
        Task waiting = pipe.WaitForConnectionAsync();

        Assert.AreEqual(Refused, await ConnectAs(standardUser!, password!, name), "another standard user is refused");
        Assert.IsFalse(waiting.IsCompleted, "nothing connected");

        Assert.AreEqual(Connected, await ConnectAs(otherAdministrator!, password!, name), "an administrator of another account is let in");
        await waiting.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.AreEqual(1, pipe.ReadByte(), "what that administrator wrote arrives");
    }

    /// <summary>
    /// Starts Windows PowerShell as <paramref name="user"/> to open the pipe and write one byte.
    /// Returns its exit code: <see cref="Connected"/>, <see cref="Refused"/>, or another number
    /// for anything else.
    /// </summary>
    private static async Task<int> ConnectAs(string user, string password, string pipeName)
    {
        string script =
            "$c = [System.IO.Pipes.NamedPipeClientStream]::new('.', '" + pipeName + "', [System.IO.Pipes.PipeDirection]::Out); " +
            "try { $c.Connect(5000); $c.WriteByte(1); $c.Flush(); $c.Dispose(); exit " + Connected + " } " +
            "catch { $e = $_.Exception; while ($e.InnerException) { $e = $e.InnerException }; " +
            "if ($e -is [System.UnauthorizedAccessException]) { exit " + Refused + " }; [Console]::Error.WriteLine($e.Message); exit 1 }";

        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe"))
        {
            UserName = user,
            PasswordInClearText = password,
            LoadUserProfile = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardError = true,
            WorkingDirectory = Environment.SystemDirectory,
        };
        foreach (string argument in new[] { "-NoProfile", "-NonInteractive", "-Command", script })
        {
            start.ArgumentList.Add(argument);
        }

        using Process client = Process.Start(start) ?? throw new InvalidOperationException("The client did not start.");
        Task<string> errors = client.StandardError.ReadToEndAsync();
        using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        await client.WaitForExitAsync(limit.Token);
        string written = await errors;
        Assert.IsTrue(client.ExitCode is Connected or Refused, $"The client as {user} ended with {client.ExitCode}: {written}");
        return client.ExitCode;
    }
}
