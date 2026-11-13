using SecReview.Probing;

namespace SecReview.Checks.BuiltIn.Programs;

/// <summary>What was found out about one file, folder or registry key.</summary>
internal enum VerdictKind
{
    /// <summary>It could not be read; <see cref="Verdict.Reason"/> says why.</summary>
    Unknown = 0,

    /// <summary>Only administrators and Windows can change it.</summary>
    Protected,

    /// <summary>Standard users can change or replace it.</summary>
    Changeable,

    /// <summary>Standard users cannot change it but can put files next to it, or into it for a folder.</summary>
    AddBeside,

    /// <summary>It is not there, and standard users cannot put it there.</summary>
    Missing,

    /// <summary>It is not there, and standard users can put something there.</summary>
    MissingCreatable,

    /// <summary>It is on another computer.</summary>
    Network,

    /// <summary>It is on a drive that can be taken out or swapped.</summary>
    NotFixedDrive,
}

/// <summary>The judgement of one place.</summary>
/// <param name="Kind">What was found.</param>
/// <param name="Path">The place judged. Empty for a network location: its name is not kept.</param>
/// <param name="Who">The groups that can change it, in words: "Users", "Authenticated Users and Users".</param>
/// <param name="Where">The file, folder or key whose permissions let them.</param>
/// <param name="Unread">How the read that stopped the judgement ended.</param>
/// <param name="Reason">Why it could not be judged.</param>
internal sealed record Verdict(
    VerdictKind Kind, string Path, string Who = "", string Where = "", ProbeStatus Unread = ProbeStatus.Ok, string? Reason = null)
{
    public bool IsProblem => Kind is VerdictKind.Changeable or VerdictKind.AddBeside or VerdictKind.MissingCreatable
        or VerdictKind.Network or VerdictKind.NotFixedDrive;

    /// <summary>Not read because that takes administrator rights; an elevated scan can.</summary>
    public bool NeedsAdministrator => Kind == VerdictKind.Unknown && Unread == ProbeStatus.AccessDenied;

    /// <summary>The judgement as a row's "found" text.</summary>
    public string Found => Kind switch
    {
        VerdictKind.Protected => "Protected",
        VerdictKind.Changeable when Same(Where, Path) => $"{Who} can change {Path}",
        VerdictKind.Changeable => $"{Path}: {Who} can change {Where}",
        VerdictKind.AddBeside when Same(Where, Path) => $"{Who} can add files to {Path}",
        VerdictKind.AddBeside => $"{Path}: {Who} can add files to {Where}",
        VerdictKind.Missing => Reason ?? $"{Path} is missing",
        VerdictKind.MissingCreatable => $"{Path} is missing and {Who} can create it",
        VerdictKind.Network => "On a network location",
        VerdictKind.NotFixedDrive => $"{Path} is on a drive that is not a fixed disk of this PC",
        _ when NeedsAdministrator => $"{Path}: reading the permissions needs administrator rights",
        _ when Path.Length == 0 => Reason ?? "It could not be told which program is meant",
        _ => Reason is null ? $"{Path}: the permissions could not be read" : $"{Path}: {Wording.LowerFirst(Reason)}",
    };

    /// <summary>
    /// What is wrong, without the file it was found for: the same for every program that
    /// suffers from the permissions of one folder.
    /// </summary>
    public string Cause => Kind switch
    {
        VerdictKind.Changeable => $"{Who} can change {Where}",
        VerdictKind.AddBeside => $"{Who} can add files to {Where}",
        _ => Found,
    };

    private static bool Same(string a, string b) => a.Equals(b, StringComparison.OrdinalIgnoreCase);
}

/// <summary>The judgement of one stored command.</summary>
/// <param name="Program">The program it runs.</param>
/// <param name="Planted">
/// A place Windows tries before that program where standard users could put another one: the
/// result of a path with spaces written without quotes, or of a name looked up along the
/// search path.
/// </param>
/// <param name="Target">What the program was asked to run, for a program that only runs what its arguments name.</param>
/// <param name="Reference">The command as it was read.</param>
internal sealed record CommandVerdict(Verdict Program, Verdict? Planted, Verdict? Target, ProgramReference Reference)
{
    public bool IsProblem => Program.IsProblem || Planted is not null || Target is { IsProblem: true };

    public bool IsUnknown => !IsProblem && (Program.Kind == VerdictKind.Unknown || Target is { Kind: VerdictKind.Unknown });

    /// <summary>Unknown only because reading takes administrator rights.</summary>
    public bool NeedsAdministrator =>
        IsUnknown &&
        (Program.Kind != VerdictKind.Unknown || Program.NeedsAdministrator) &&
        (Target is not { Kind: VerdictKind.Unknown } || Target.NeedsAdministrator);

    public bool IsMissing => !IsProblem && !IsUnknown && (Program.Kind == VerdictKind.Missing || Target is { Kind: VerdictKind.Missing });

    /// <summary>The judgement as a row's "found" text: the first thing wrong, else the program's state.</summary>
    public string Found =>
        Program.IsProblem ? Program.Found
        : Target is { IsProblem: true } ? Target.Found
        : Planted is not null ? PlantedFound
        : Program.Kind == VerdictKind.Unknown ? Program.Found
        : Target is { Kind: VerdictKind.Unknown or VerdictKind.Missing } ? Target.Found
        : Program.Found;

    /// <summary>What is wrong, the same for every command that suffers from the permissions of one folder.</summary>
    public string Cause =>
        Program.IsProblem ? Program.Cause
        : Target is { IsProblem: true } ? Target.Cause
        : Found;

    private string PlantedFound => Reference.ByName
        ? $"Named without a folder; {Planted!.Who} can create {Planted.Path}, which Windows would run first"
        : $"Written without quotes; {Planted!.Who} can create {Planted.Path}, which Windows would run first";
}

/// <summary>
/// Says whether standard users can change a program, a folder or a registry key, from the
/// permissions of the thing and of every folder above it. Network locations are never opened
/// and links are never followed. Use one per check run.
/// </summary>
internal sealed class ProgramJudge(IAccessProbe access)
{
    private readonly Dictionary<string, Verdict> _files = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, Verdict> _folders = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>A program or library file.</summary>
    public Verdict File(string path) => Cached(_files, path, asFolder: false);

    /// <summary>A folder that programs are looked for in.</summary>
    public Verdict Folder(string path) => Cached(_folders, path, asFolder: true);

    /// <summary>A registry key that says what runs.</summary>
    public Verdict Key(RegistryRoot root, string key)
    {
        string name = $@"{(root == RegistryRoot.CurrentUser ? "HKCU" : "HKLM")}\{key}";
        ProbeResult<SecurityReading> read = access.ReadKey(root, key);
        if (read.Status == ProbeStatus.NotFound)
        {
            return new Verdict(VerdictKind.Missing, name);
        }

        if (!read.IsOk)
        {
            return new Verdict(VerdictKind.Unknown, name, Unread: read.Status, Reason: read.Detail);
        }

        const ChangeRights Change = ChangeRights.WriteContent | ChangeRights.AddSubfolder | ChangeRights.Control;
        ChangeAccess rights = AccessRules.Evaluate(read.Value!);
        return rights.Has(Change)
            ? new Verdict(VerdictKind.Changeable, name, rights.Who(Change), name)
            : new Verdict(VerdictKind.Protected, name);
    }

    /// <summary>The program a stored command runs, and anything Windows would try before it.</summary>
    public CommandVerdict Command(ProgramReference reference)
    {
        ArgumentNullException.ThrowIfNull(reference);
        switch (reference.Kind)
        {
            case ReferenceKind.Network:
                return new CommandVerdict(new Verdict(VerdictKind.Network, string.Empty), null, null, reference);
            case ReferenceKind.Local when reference.Candidates.Count > 0:
                break;
            default:
                return new CommandVerdict(
                    new Verdict(VerdictKind.Unknown, string.Empty, Reason: reference.Problem ?? "No program is named."), null, null, reference);
        }

        // Windows runs the first candidate that exists. Each earlier one is a place where a
        // program could be put to run instead.
        Verdict? program = null;
        Verdict? planted = null;
        foreach (string candidate in reference.Candidates)
        {
            Verdict verdict = File(candidate);
            if (verdict.Kind == VerdictKind.MissingCreatable)
            {
                planted ??= verdict;
            }
            else if (verdict.Kind != VerdictKind.Missing)
            {
                program = verdict;
                break;
            }
        }

        if (program is null)
        {
            // Nothing is there. The file that was meant is the one that is missing; a place
            // tried before it still counts.
            program = File(reference.Intended);
            if (reference.ByName)
            {
                program = new Verdict(VerdictKind.Missing, System.IO.Path.GetFileName(reference.Intended));
            }
            else if (!reference.Complete || planted?.Path.Equals(program.Path, StringComparison.OrdinalIgnoreCase) == true)
            {
                // Where the program's name ends was a guess: only the first candidate is
                // sure to hold no argument, and that one is the program judged.
                planted = null;
            }
        }

        Verdict? target = null;
        if (reference.Target is { PerUser: false } named)
        {
            CommandVerdict inner = Command(named);
            target = inner.Planted is { } before && !inner.Program.IsProblem ? before : inner.Program;
        }

        return new CommandVerdict(program, planted, target, reference);
    }

    private Verdict Cached(Dictionary<string, Verdict> seen, string path, bool asFolder)
    {
        if (!seen.TryGetValue(path, out Verdict? verdict))
        {
            seen[path] = verdict = Judge(path, asFolder);
        }

        return verdict;
    }

    private Verdict Judge(string path, bool asFolder)
    {
        string full = path.Replace('/', '\\').TrimEnd(' ');
        if (full.StartsWith(@"\\", StringComparison.Ordinal))
        {
            return new Verdict(VerdictKind.Network, string.Empty);
        }

        if (!MachineContext.IsLocalPath(full) || full.Length > ProgramReference.MaximumLength || full.Any(c => char.IsControl(c) || c is '<' or '>' or '|' or '"' or '*' or '?') ||
            full.AsSpan(2).Contains(':'))
        {
            return new Verdict(VerdictKind.Unknown, path, Reason: "The path is not one on a drive of this PC.");
        }

        ProbeResult<DriveKind> drive = access.Drive(full[0]);
        switch (drive)
        {
            case { IsOk: false }:
                return new Verdict(VerdictKind.Unknown, full, Unread: drive.Status, Reason: drive.Detail);
            case { Value: DriveKind.Network }:
                return new Verdict(VerdictKind.Network, string.Empty);
            case { Value: DriveKind.Absent }:
                return new Verdict(VerdictKind.Missing, full, Reason: $"{full} is on a drive that is not there");
            case { Value: DriveKind.Removable or DriveKind.Other }:
                return new Verdict(VerdictKind.NotFixedDrive, full);
            case { Value: DriveKind.Unknown }:
                return new Verdict(VerdictKind.Unknown, full, Reason: "Windows did not say what kind of drive it is on.");
        }

        // From the top of the drive down: whoever can replace a folder can replace all that is in it.
        string[] parts = full[3..].Split('\\', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Any(part => part is "." or ".."))
        {
            return new Verdict(VerdictKind.Unknown, path, Reason: "The path is not written out in full.");
        }

        string place = full[..3];
        full = parts.Length == 0 ? place : place + string.Join('\\', parts);
        ChangeAccess? above = null;
        string abovePath = string.Empty;
        for (int index = -1; index < parts.Length; index++)
        {
            if (index >= 0)
            {
                place = index == 0 ? place + parts[0] : $@"{place}\{parts[index]}";
            }

            bool last = index == parts.Length - 1;
            ProbeResult<SecurityReading> read = access.ReadPath(place);
            if (read.Status == ProbeStatus.NotFound)
            {
                ChangeRights create = last && !asFolder ? ChangeRights.AddFile : ChangeRights.AddSubfolder;
                return above is not null && above.Has(create)
                    ? new Verdict(VerdictKind.MissingCreatable, full, above.Who(create), abovePath)
                    : new Verdict(VerdictKind.Missing, full);
            }

            if (!read.IsOk)
            {
                return new Verdict(
                    VerdictKind.Unknown,
                    full,
                    Unread: read.Status,
                    Reason: read.Detail == IAccessProbe.LinkDetail ? "The path goes through a link, which is not followed." : read.Detail);
            }

            bool isFile = read.Value!.Kind == SecuredKind.File;
            if (isFile && !last)
            {
                return new Verdict(VerdictKind.Missing, full);
            }

            ChangeAccess here = AccessRules.Evaluate(read.Value);
            const ChangeRights Content = ChangeRights.WriteContent | ChangeRights.Control;
            if (here.Has(isFile ? Content : ChangeRights.Control))
            {
                return new Verdict(VerdictKind.Changeable, full, here.Who(isFile ? Content : ChangeRights.Control), place);
            }

            // Moved out of the way and made anew: needs the right to remove it and the right
            // to create its like in the folder above.
            ChangeRights remake = isFile ? ChangeRights.AddFile : ChangeRights.AddSubfolder;
            if (above is not null && above.Has(remake) && (above.Has(ChangeRights.DeleteChildren) || here.Has(ChangeRights.Delete)))
            {
                return new Verdict(VerdictKind.Changeable, full, above.Who(remake), place);
            }

            if (last)
            {
                // Nothing lets them change it. A file put beside a program, or into a folder
                // that programs are looked for in, is still loaded or run.
                ChangeAccess? folder = isFile ? above : here;
                return folder is not null && folder.Has(ChangeRights.AddFile)
                    ? new Verdict(VerdictKind.AddBeside, full, folder.Who(ChangeRights.AddFile), isFile ? abovePath : place)
                    : new Verdict(VerdictKind.Protected, full);
            }

            (above, abovePath) = (here, place);
        }

        return new Verdict(VerdictKind.Protected, full);
    }
}
