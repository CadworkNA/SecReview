using System.Globalization;
using System.Security.Cryptography;
using SecReview.Malware;

// Usage:
//   SecReviewIndexBuilder <folder of advisories> <output file> [--source <text>] [--minimum <count>]
//   SecReviewIndexBuilder --check <index file>
//
// The first form reads every *.json under the folder (osv/malicious of the OpenSSF
// malicious-packages feed) and writes the list of known-malicious packages SecReview ships.
// Without --minimum the list must be what a published list is: enough packages overall and
// per registry. The second form says whether an existing list may go into a build that
// ships: it loads, comes from the feed, is recent and is large enough.
//
// Exit code 0 when the list was written or is fit to ship, 1 when not, 2 for wrong arguments.
// Advisories are only parsed: nothing from the feed is run, followed (links are skipped) or
// written anywhere.

const int Ok = 0;
const int Failed = 1;
const int Usage = 2;

if (args is ["--check", var listed])
{
    return Check(listed);
}

string? folder = null;
string? output = null;
string source = "ossf/malicious-packages";
MalwareIndexRequirements requirements = MalwareIndexRequirements.Published;

for (int i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--source" when i + 1 < args.Length:
            source = args[++i];
            break;
        case "--minimum" when i + 1 < args.Length && int.TryParse(args[i + 1], NumberStyles.None, CultureInfo.InvariantCulture, out int count):
            requirements = MalwareIndexRequirements.AtLeast(count);
            i++;
            break;
        case var text when !text.StartsWith('-') && folder is null:
            folder = text;
            break;
        case var text when !text.StartsWith('-') && output is null:
            output = text;
            break;
        default:
            return WrongArguments($"Unexpected argument: {args[i]}");
    }
}

if (folder is null || output is null)
{
    return WrongArguments("A folder of advisories and an output file are needed.");
}

if (!Directory.Exists(folder))
{
    Console.Error.WriteLine($"No such folder: {folder}");
    return Failed;
}

var build = new MalwareIndexBuild();
var walk = new EnumerationOptions
{
    RecurseSubdirectories = true,
    AttributesToSkip = FileAttributes.ReparsePoint,
    IgnoreInaccessible = false,
    MatchCasing = MatchCasing.CaseInsensitive,
};

foreach (string path in Directory.EnumerateFiles(folder, "*.json", walk))
{
    try
    {
        var file = new FileInfo(path);
        if (file.Length > AdvisoryReader.MaximumBytes)
        {
            build.AddUnreadable();
            continue;
        }

        build.Add(File.ReadAllBytes(path));
    }
    catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
    {
        build.AddUnreadable();
    }
}

// Whole seconds, as the index stores them.
DateTimeOffset built = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
MalwareIndexBuildResult result = build.Finish(built, source, requirements);
foreach (string line in result.Report)
{
    Console.Out.WriteLine(line);
}

if (result.Index is not { } index)
{
    Console.Error.WriteLine(result.Problem);
    return Failed;
}

File.WriteAllBytes(output, index);
Console.Out.WriteLine($"Written: {output}");
Console.Out.WriteLine($"SHA-256: {Convert.ToHexStringLower(SHA256.HashData(index))}");
Console.Out.WriteLine($"Source:  {source}, built {built:yyyy-MM-dd HH:mm:ss} UTC");
return Ok;

static int Check(string path)
{
    byte[] bytes;
    try
    {
        var file = new FileInfo(path);
        if (!file.Exists || file.Length > MalwareIndex.MaximumBytes)
        {
            Console.Error.WriteLine($"Not a list of known-malicious packages: {path}");
            return Failed;
        }

        bytes = File.ReadAllBytes(path);
    }
    catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
    {
        Console.Error.WriteLine($"The list could not be read: {exception.Message}");
        return Failed;
    }

    MalwareIndexLoad load = MalwareIndex.Load(bytes);
    if (load.Index is not { } list)
    {
        Console.Error.WriteLine($"The list cannot be used: {load.Problem}.");
        return Failed;
    }

    if (MalwareIndexRequirements.Shipped.Problem(list, DateTimeOffset.UtcNow) is { } problem)
    {
        Console.Error.WriteLine(problem);
        return Failed;
    }

    Console.Out.WriteLine($"{list.Count} packages, built {list.Built:yyyy-MM-dd HH:mm:ss} UTC from {list.Source}.");
    return Ok;
}

static int WrongArguments(string message)
{
    Console.Error.WriteLine(message);
    Console.Error.WriteLine("Usage: SecReviewIndexBuilder <folder of advisories> <output file> [--source <text>] [--minimum <count>]");
    Console.Error.WriteLine("       SecReviewIndexBuilder --check <index file>");
    return Usage;
}
