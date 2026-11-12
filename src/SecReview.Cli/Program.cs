using SecReview;
using SecReview.CommandLine;

switch (CliArguments.Parse(args))
{
    case HelpCommand:
        Console.Out.WriteLine(CliArguments.Usage);
        return ExitCode.Ok;

    case VersionCommand:
        Console.Out.WriteLine($"{ProductInfo.Name} {ProductInfo.Version}");
        return ExitCode.Ok;

    case InvalidCommand invalid:
        Console.Error.WriteLine(invalid.Message);
        Console.Error.WriteLine(CliArguments.Usage);
        return ExitCode.Usage;

    default:
        throw new InvalidOperationException("Unhandled command.");
}
