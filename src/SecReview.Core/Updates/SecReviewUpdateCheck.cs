using System.Text;
using SecReview.Checks;
using SecReview.Diagnostics;
using SecReview.Probing;
using SecReview.Scanning;

namespace SecReview.Updates;

/// <summary>
/// SecReview itself is up to date. The check does not go to the network: it reads what the
/// app last found (<see cref="UpdateState"/>). Not knowing is said as such, with the reason,
/// and never passes.
/// </summary>
/// <param name="source">Where this build looks for updates; the compiled-in one by default.</param>
/// <param name="dataFolder">SecReview's data folder; the real one by default.</param>
/// <param name="installed">The running version; this build's by default.</param>
public sealed class SecReviewUpdateCheck(UpdateSource? source = null, Func<string>? dataFolder = null, string? installed = null) : ICheck
{
    public const string Id = "updates.secreview";

    /// <summary>What SecReview found longer ago than this no longer says whether it is up to date.</summary>
    public static readonly TimeSpan MaximumAge = TimeSpan.FromDays(7);

    private const string Item = "SecReview";

    private readonly UpdateSource _source = source ?? UpdateSource.Compiled;
    private readonly Func<string> _dataFolder = dataFolder ?? (() => AppData.Directory);
    private readonly string _installed = installed ?? ProductInfo.Version;

    // It reads SecReview's own file in the user's profile.
    public CheckDefinition Definition { get; } = new(Id, CheckCategory.Updates, Severity.Low, Scope: CheckScope.User);

    public CheckOutcome Run(CheckContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!_source.IsConfigured)
        {
            return CheckOutcome.NotApplicable("This build of SecReview does not look for updates.");
        }

        if (UpdatePolicy.Read(context.Probes.Registry).NoUpdateCheck)
        {
            return CheckOutcome.NotApplicable("Your organisation has switched off SecReview's look for updates.") with { ManagedByPolicy = true };
        }

        DateTimeOffset now = context.Clock.GetUtcNow();
        string path = Path.Combine(_dataFolder(), UpdateState.FileName);
        ProbeResult<string> file = context.Probes.Files.ReadText(path, 64 * 1024);
        UpdateState state = (file.IsOk ? UpdateStateStore.FromBytes(Encoding.UTF8.GetBytes(file.Value!)) : new UpdateState()).For(_installed, now);

        string expected = "The newest version";
        switch (state.Outcome)
        {
            case UpdateOutcome.Available:
                string age = state.Published is { } published ? $", released {ScanPresentation.Age(published, now)}" : string.Empty;
                return CheckOutcome.Fail(
                    $"Version {state.Available} of SecReview is available{age}.",
                    Finding.Problem(Item, $"Version {_installed}", $"Version {state.Available}"));

            case UpdateOutcome.UpToDate when now - state.CheckedAt!.Value <= MaximumAge:
                return CheckOutcome.Pass(
                    "SecReview is up to date.", Finding.Ok(Item, $"Version {_installed}, the newest", expected));

            case UpdateOutcome.Failed when now - state.CheckedAt!.Value <= MaximumAge:
                return CheckOutcome.Error(state.Problem ?? "SecReview could not look for updates.");

            default:
                // Never looked (the window or the icon does, once a day), or too long ago to count.
                return CheckOutcome.Error(state.CheckedAt is null
                    ? "SecReview has not looked for updates yet."
                    : $"SecReview last looked for updates {ScanPresentation.Age(state.CheckedAt.Value, now)}.");
        }
    }
}
