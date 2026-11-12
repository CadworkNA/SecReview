using System.Globalization;
using System.Security.Cryptography;
using SecReview.Malware;

// Usage: SecReviewIndexBuilder <folder of advisories> <output file> [--source <text>] [--minimum <count>]
//
// Reads every *.json under the folder (osv/malicious of the OpenSSF malicious-packages feed)
// and writes the list of known-malicious packages SecReview ships. Exit code 0 when the list
// was written, 1 when it was not, 2 for wrong arguments. Advisories are only parsed: nothing
// from the feed is run, followed (links are skipped) or written anywhere.

const int Ok = 0;
const int Failed = 1;
const int Usage = 2;

string? folder = null;
string? output = null;
string source = "ossf/malicious-packages";
int minimum = 1000;

for (int i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--source" when i + 1 < args.Length:
            source = args[++i];
            break;
        case "--minimum" when i + 1 < args.Length && int.TryParse(args[i + 1], NumberStyles.None, CultureInfo.InvariantCulture, out int count):
            minimum = count;
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
MalwareIndexBuildResult result = build.Finish(built, source, minimum);
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

static int WrongArguments(string message)
{
    Console.Error.WriteLine(message);
    Console.Error.WriteLine("Usage: SecReviewIndexBuilder <folder of advisories> <output file> [--source <text>] [--minimum <count>]");
    return Usage;
}
