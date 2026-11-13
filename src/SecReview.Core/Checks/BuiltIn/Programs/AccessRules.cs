using SecReview.Probing;

namespace SecReview.Checks.BuiltIn.Programs;

/// <summary>The ways a file, folder or registry key can be changed.</summary>
[Flags]
internal enum ChangeRights
{
    None = 0,

    /// <summary>Write into the file, or set a value in the key.</summary>
    WriteContent = 1,

    /// <summary>Create a file in the folder.</summary>
    AddFile = 2,

    /// <summary>Create a subfolder, or a subkey.</summary>
    AddSubfolder = 4,

    /// <summary>Delete what is in the folder, whatever its own permissions say.</summary>
    DeleteChildren = 8,

    /// <summary>Delete or rename it.</summary>
    Delete = 16,

    /// <summary>Rewrite its permissions, and so take any other right.</summary>
    ChangePermissions = 32,

    /// <summary>Become its owner, and so rewrite its permissions.</summary>
    TakeOwnership = 64,

    /// <summary>The rights that hand over everything else.</summary>
    Control = ChangePermissions | TakeOwnership,

    All = WriteContent | AddFile | AddSubfolder | DeleteChildren | Delete | Control,
}

/// <summary>What one group of ordinary accounts may change.</summary>
/// <param name="Name">The group's name as Windows shows it in English: "Users".</param>
/// <param name="Rights">What it may do.</param>
internal sealed record GroupRights(string Name, ChangeRights Rights);

/// <summary>Who, besides administrators and Windows itself, may change something.</summary>
/// <param name="Groups">The groups every standard user is in, or can be in, that may change it.</param>
/// <param name="OtherAccounts">
/// How many named accounts may change it. Whether such an account is an administrator cannot
/// be told from here, so they are counted and not judged.
/// </param>
internal sealed record ChangeAccess(IReadOnlyList<GroupRights> Groups, int OtherAccounts)
{
    /// <summary>Everything the groups may do, together.</summary>
    public ChangeRights Rights { get; } = Groups.Aggregate(ChangeRights.None, (all, group) => all | group.Rights);

    public bool Has(ChangeRights any) => (Rights & any) != 0;

    /// <summary>The groups holding any of these rights: "Users", "Authenticated Users and Users".</summary>
    public string Who(ChangeRights any = ChangeRights.All) =>
        Wording.JoinWithAnd([.. Groups.Where(group => (group.Rights & any) != 0).Select(group => group.Name)]);
}

/// <summary>
/// Reads a permission list the way Windows applies it, for the groups that standard users
/// belong to. Errs towards saying that a group can change something: a deny entry counts only
/// when it is certain to apply to every member of the group that an allow entry names.
/// </summary>
internal static class AccessRules
{
    private const string Everyone = "S-1-1-0";
    private const string AuthenticatedUsers = "S-1-5-11";
    private const string OwnerRights = "S-1-3-4";

    private const uint GenericAll = 0x10000000;
    private const uint GenericWrite = 0x40000000;
    private const uint Delete = 0x10000;
    private const uint WriteDac = 0x40000;
    private const uint WriteOwner = 0x80000;

    /// <summary>
    /// Groups that hold standard users, most general first, with the groups whose members
    /// they all are. Service accounts, app containers and administrators are not here.
    /// </summary>
    private static readonly (string Sid, string Name, string[] AlsoIn)[] Groups =
    [
        (Everyone, "Everyone", []),
        (AuthenticatedUsers, "Authenticated Users", [Everyone]),
        ("S-1-5-32-545", "Users", [Everyone, AuthenticatedUsers]),
        ("S-1-5-4", "Interactive", [Everyone]),
        ("S-1-5-32-546", "Guests", [Everyone]),
        ("S-1-5-7", "Anonymous", []),
        ("S-1-5-2", "Network", [Everyone]),
        ("S-1-5-3", "Batch", [Everyone]),
        ("S-1-5-14", "Remote Interactive", [Everyone]),
        ("S-1-5-15", "This Organization", [Everyone]),
        ("S-1-2-0", "Local", [Everyone]),
        ("S-1-2-1", "Console Logon", [Everyone]),
        ("S-1-5-113", "Local account", [Everyone]),
        ("S-1-5-32-555", "Remote Desktop Users", [Everyone]),
    ];

    /// <summary>The last number of a domain's or PC's own groups for ordinary accounts.</summary>
    private static readonly (string Rid, string Name)[] DomainGroups =
    [
        ("-513", "Domain Users"),
        ("-514", "Domain Guests"),
        ("-515", "Domain Computers"),
        ("-501", "Guest"),
    ];

    /// <summary>The last number of accounts and groups that are administrators by definition.</summary>
    private static readonly string[] DomainAdministrators = ["-500", "-512", "-518", "-519"];

    public static ChangeAccess Evaluate(SecurityReading reading)
    {
        ArgumentNullException.ThrowIfNull(reading);

        // No list at all: Windows lets everyone do everything.
        if (!reading.HasList)
        {
            return new ChangeAccess([new GroupRights("Everyone", ChangeRights.All)], 0);
        }

        var rights = new Dictionary<string, ChangeRights>(StringComparer.Ordinal);
        var others = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string sid in reading.Entries.Where(e => e.Allows && !e.InheritOnly).Select(e => e.Sid).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            ChangeRights granted = Granted(reading, sid);
            if (granted == ChangeRights.None)
            {
                continue;
            }

            if (GroupName(sid) is { } name)
            {
                rights[name] = rights.GetValueOrDefault(name) | granted;
            }
            else if (IsNamedAccount(sid))
            {
                others.Add(sid);
            }
        }

        // An owner may always rewrite the permissions, unless an entry for "owner rights" says
        // what the owner gets instead.
        if (GroupName(reading.Owner) is { } owner)
        {
            ChangeRights asOwner = reading.Entries.Any(e => !e.InheritOnly && Is(e.Sid, OwnerRights))
                ? Granted(reading, OwnerRights)
                : ChangeRights.ChangePermissions;
            if (asOwner != ChangeRights.None)
            {
                rights[owner] = rights.GetValueOrDefault(owner) | asOwner;
            }
        }

        string[] order = [.. Groups.Select(g => g.Name), .. DomainGroups.Select(g => g.Name)];
        return new ChangeAccess(
            [.. rights.OrderBy(r => Array.IndexOf(order, r.Key)).Select(r => new GroupRights(r.Key, r.Value))],
            others.Count);
    }

    /// <summary>
    /// What the allow entries for one identity give it, after the deny entries that apply to
    /// everyone holding that identity. Entries are applied in order, as Windows does: a deny
    /// after an allow comes too late.
    /// </summary>
    private static ChangeRights Granted(SecurityReading reading, string sid)
    {
        string[] alsoIn = Groups.FirstOrDefault(g => Is(g.Sid, sid)).AlsoIn
            ?? (DomainGroups.Any(g => IsDomain(sid, g.Rid)) ? [Everyone, AuthenticatedUsers] : []);

        uint granted = 0;
        uint denied = 0;
        foreach (PermissionEntry entry in reading.Entries)
        {
            if (entry.InheritOnly)
            {
                continue;
            }

            uint mask = Specific(reading.Kind, entry.Rights);
            if (entry.Allows)
            {
                if (Is(entry.Sid, sid))
                {
                    granted |= mask & ~denied;
                }
            }
            else if (!entry.Conditional && (Is(entry.Sid, sid) || alsoIn.Any(group => Is(group, entry.Sid))))
            {
                denied |= mask & ~granted;
            }
        }

        return Changes(reading.Kind, granted);
    }

    /// <summary>The mask with its generic bits turned into the rights they stand for.</summary>
    private static uint Specific(SecuredKind kind, uint mask)
    {
        if ((mask & GenericAll) != 0)
        {
            mask |= kind == SecuredKind.RegistryKey ? 0xF003Fu : 0x1F01FFu;
        }

        if ((mask & GenericWrite) != 0)
        {
            mask |= kind == SecuredKind.RegistryKey ? 0x20006u : 0x120116u;
        }

        return mask;
    }

    private static ChangeRights Changes(SecuredKind kind, uint mask)
    {
        ChangeRights rights = ChangeRights.None;
        rights |= (mask & Delete) != 0 ? ChangeRights.Delete : 0;
        rights |= (mask & WriteDac) != 0 ? ChangeRights.ChangePermissions : 0;
        rights |= (mask & WriteOwner) != 0 ? ChangeRights.TakeOwnership : 0;
        rights |= kind switch
        {
            // Write data, append data.
            SecuredKind.File => (mask & 0x6) != 0 ? ChangeRights.WriteContent : 0,

            // Add file, add subfolder, delete child.
            SecuredKind.Folder =>
                ((mask & 0x2) != 0 ? ChangeRights.AddFile : 0) |
                ((mask & 0x4) != 0 ? ChangeRights.AddSubfolder : 0) |
                ((mask & 0x40) != 0 ? ChangeRights.DeleteChildren : 0),

            // Set value; create subkey, create link.
            _ =>
                ((mask & 0x2) != 0 ? ChangeRights.WriteContent : 0) |
                ((mask & 0x24) != 0 ? ChangeRights.AddSubfolder : 0),
        };
        return rights;
    }

    private static string? GroupName(string sid) =>
        Groups.FirstOrDefault(g => Is(g.Sid, sid)).Name ?? DomainGroups.FirstOrDefault(g => IsDomain(sid, g.Rid)).Name;

    /// <summary>
    /// An account or group a person made (on this PC, in a domain or in a directory), other
    /// than those that are administrators by definition.
    /// </summary>
    private static bool IsNamedAccount(string sid) =>
        sid.StartsWith("S-1-12-1-", StringComparison.OrdinalIgnoreCase) ||
        (sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase) && !DomainAdministrators.Any(rid => IsDomain(sid, rid)));

    private static bool IsDomain(string sid, string rid) =>
        sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase) && sid.EndsWith(rid, StringComparison.Ordinal);

    private static bool Is(string a, string b) => a.Equals(b, StringComparison.OrdinalIgnoreCase);
}
