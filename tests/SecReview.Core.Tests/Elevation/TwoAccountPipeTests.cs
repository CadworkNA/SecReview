using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.Versioning;
using SecReview.Elevation;

namespace SecReview.Tests.Elevation;

/// <summary>
/// The administrator pipe, as the window makes it, with clients from two other accounts.
/// Another standard user is refused, and so is an administrator of another account without
/// elevation (what a program of theirs has before the Windows prompt). The same administrator
/// with elevation, which is what the helper has after the prompt, is let in. Needs two accounts
/// on the machine, so it runs on GitHub's disposable build machines only, through
/// <c>scripts/test-two-accounts.ps1</c>; anywhere else it says so.
/// </summary>
[TestClass]
[SupportedOSPlatform("windows")]
public sealed class TwoAccountPipeTests
{
    private const string StandardUserVariable = "SECREVIEW_TEST_STANDARD_USER";
    private const string OtherAdministratorVariable = "SECREVIEW_TEST_OTHER_ADMINISTRATOR";
    private const string PasswordVariable = "SECREVIEW_TEST_PASSWORD";

    private static readonly string PowerShell = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");

    /// <summary>What a client reports: whether it got in, and whether it ran elevated.</summary>
    private sealed record Attempt(string Outcome, bool Elevated);

    [TestMethod]
    [TestCategory("TwoAccounts")]
    public async Task OnlyAnElevatedAdministrator_GetsIn_FromAnyAccount()
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

        string folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SecReviewPipeTest-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            string name = ElevationPipe.NewName();
            using NamedPipeServerStream pipe = AdministratorScan.CreatePipe(name, alsoThisUser: false);
            Task waiting = pipe.WaitForConnectionAsync();

            Attempt standard = await StartedWithPassword(standardUser!, password!, name, folder);
            Assert.AreEqual(new Attempt("refused", Elevated: false), standard, "another standard user is refused");

            Attempt notElevated = await StartedWithPassword(otherAdministrator!, password!, name, folder);
            Assert.AreEqual(new Attempt("refused", Elevated: false), notElevated, "another administrator is refused before elevation");
            Assert.IsFalse(waiting.IsCompleted, "nothing connected");

            Attempt elevated = await StartedElevated(otherAdministrator!, password!, name, folder);
            Assert.AreEqual(new Attempt("connected", Elevated: true), elevated, "an elevated administrator of another account is let in");
            await waiting.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.AreEqual(1, pipe.ReadByte(), "what that administrator wrote arrives");
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    }

    /// <summary>
    /// The client: opens the pipe, writes one byte, and writes "outcome|elevated" to the result
    /// file. Outcome is "connected", "refused" or the error.
    /// </summary>
    private static string ClientScript(string pipeName, string resultPath) =>
        "$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)\r\n" +
        "$c = [System.IO.Pipes.NamedPipeClientStream]::new('.', '" + pipeName + "', [System.IO.Pipes.PipeDirection]::Out)\r\n" +
        "try { $c.Connect(5000); $c.WriteByte(1); $c.Flush(); $c.Dispose(); $outcome = 'connected' }\r\n" +
        "catch { $e = $_.Exception; while ($e.InnerException) { $e = $e.InnerException }\r\n" +
        "  $outcome = if ($e -is [System.UnauthorizedAccessException]) { 'refused' } else { $e.Message } }\r\n" +
        "Set-Content -LiteralPath '" + resultPath + "' -Value \"$outcome|$elevated\" -Encoding ASCII\r\n";

    /// <summary>
    /// Started with the account's password (CreateProcessWithLogonW): what a program of that
    /// user runs with, without elevation.
    /// </summary>
    private static async Task<Attempt> StartedWithPassword(string user, string password, string pipeName, string folder)
    {
        string result = Path.Combine(folder, user + "-password.txt");
        string script = Path.Combine(folder, user + "-password.ps1");
        await File.WriteAllTextAsync(script, ClientScript(pipeName, result));

        var start = new ProcessStartInfo(PowerShell)
        {
            UserName = user,
            PasswordInClearText = password,
            LoadUserProfile = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = Environment.SystemDirectory,
        };
        foreach (string argument in new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script })
        {
            start.ArgumentList.Add(argument);
        }

        using Process client = Process.Start(start) ?? throw new InvalidOperationException("The client did not start.");
        using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        await client.WaitForExitAsync(limit.Token);
        return await ReadResult(result, user);
    }

    /// <summary>
    /// Started as a scheduled task that runs with the account's highest rights: for an
    /// administrator, the full rights the helper has after the Windows prompt.
    /// </summary>
    private static async Task<Attempt> StartedElevated(string user, string password, string pipeName, string folder)
    {
        string result = Path.Combine(folder, user + "-elevated.txt");
        string script = Path.Combine(folder, user + "-elevated.ps1");
        await File.WriteAllTextAsync(script, ClientScript(pipeName, result));
        string task = "SecReviewPipeTest-" + Guid.NewGuid().ToString("N");

        string register =
            $"$a = New-ScheduledTaskAction -Execute '{PowerShell}' -Argument '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{script}\"'; " +
            $"Register-ScheduledTask -TaskName '{task}' -Action $a -User $env:SR_TASK_USER -Password $env:SR_TASK_PASSWORD -RunLevel Highest -Force | Out-Null; " +
            $"Start-ScheduledTask -TaskName '{task}'";
        try
        {
            await RunPowerShell(register, ("SR_TASK_USER", user), ("SR_TASK_PASSWORD", password));
            for (int attempt = 0; attempt < 60 && !File.Exists(result); attempt++)
            {
                await Task.Delay(TimeSpan.FromSeconds(1));
            }

            await Task.Delay(TimeSpan.FromMilliseconds(500));
            if (!File.Exists(result))
            {
                // Say what Task Scheduler made of it: state, last result, last run.
                string state = await RunPowerShell(
                    $"$t = Get-ScheduledTask -TaskName '{task}'; $i = $t | Get-ScheduledTaskInfo; " +
                    "\"state $($t.State), last result 0x$('{0:X}' -f $i.LastTaskResult), last run $($i.LastRunTime), logon $($t.Principal.LogonType), level $($t.Principal.RunLevel)\"");
                Assert.Fail($"The elevated client as {user} wrote no result; task: {state.Trim()}");
            }

            return await ReadResult(result, user);
        }
        finally
        {
            await RunPowerShell($"Unregister-ScheduledTask -TaskName '{task}' -Confirm:$false -ErrorAction SilentlyContinue");
        }
    }

    private static async Task<string> RunPowerShell(string command, params (string Name, string Value)[] environment)
    {
        var start = new ProcessStartInfo(PowerShell)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (string argument in new[] { "-NoProfile", "-NonInteractive", "-Command", command })
        {
            start.ArgumentList.Add(argument);
        }

        foreach ((string name, string value) in environment)
        {
            start.Environment[name] = value;
        }

        using Process process = Process.Start(start) ?? throw new InvalidOperationException("PowerShell did not start.");
        Task<string> output = process.StandardOutput.ReadToEndAsync();
        Task<string> errors = process.StandardError.ReadToEndAsync();
        using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        await process.WaitForExitAsync(limit.Token);
        string written = await errors;
        Assert.AreEqual(0, process.ExitCode, $"PowerShell failed: {written}");
        return await output;
    }

    private static async Task<Attempt> ReadResult(string path, string user)
    {
        Assert.IsTrue(File.Exists(path), $"The client as {user} wrote no result.");
        string[] parts = (await File.ReadAllTextAsync(path)).Trim().Split('|');
        Assert.AreEqual(2, parts.Length, $"The client as {user} wrote: {string.Join('|', parts)}");
        return new Attempt(parts[0], bool.Parse(parts[1]));
    }
}
