using SecReview.Probing;

namespace SecReview.Tests.Fakes;

/// <summary>
/// Permissions for a fake file, folder or registry key, said once and turned into the right
/// bits for each kind. Built from the groups a test cares about; administrators and the
/// system always have full control, as on Windows.
/// </summary>
internal sealed class FakeAccess
{
    public const string Everyone = "S-1-1-0";
    public const string AuthenticatedUsers = "S-1-5-11";
    public const string Users = "S-1-5-32-545";
    public const string Interactive = "S-1-5-4";
    public const string Administrators = "S-1-5-32-544";
    public const string System = "S-1-5-18";
    public const string TrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

    /// <summary>A made-up named account, as a list would hold one.</summary>
    public const string SomeAccount = "S-1-5-21-1111111111-2222222222-3333333333-1001";

    /// <summary>How much an entry gives.</summary>
    public enum Level
    {
        Read,

        /// <summary>Read, and create files in a folder (or set values in a key), nothing else.</summary>
        Add,

        /// <summary>Read, and create subfolders (or subkeys), nothing else. What Windows gives users on a drive's top folder.</summary>
        AddFolders,
        Modify,
        Full,
    }

    private readonly List<(string Sid, Level Level, bool Allows, bool InheritOnly)> _grants = [];

    private string _owner = Administrators;
    private bool _hasList = true;

    private FakeAccess()
    {
    }

    /// <summary>Only administrators and the system can change it; users can read. The Windows default for programs.</summary>
    public static FakeAccess Protected => new FakeAccess().Allow(Users, Level.Read);

    /// <summary>Users can change it.</summary>
    public static FakeAccess UsersModify => Protected.Allow(Users, Level.Modify);

    /// <summary>Users can add files (or values) but not change what is there.</summary>
    public static FakeAccess UsersAdd => Protected.Allow(Users, Level.Add);

    /// <summary>Everyone has full control.</summary>
    public static FakeAccess EveryoneFull => Protected.Allow(Everyone, Level.Full);

    /// <summary>No permission list at all: everyone can do everything.</summary>
    public static FakeAccess NoList => new() { _hasList = false };

    public FakeAccess Allow(string sid, Level level, bool inheritOnly = false)
    {
        _grants.Add((sid, level, true, inheritOnly));
        return this;
    }

    /// <summary>A deny entry; Windows lists these first, and so does this.</summary>
    public FakeAccess Deny(string sid, Level level)
    {
        _grants.Insert(0, (sid, level, false, false));
        return this;
    }

    public FakeAccess OwnedBy(string sid)
    {
        _owner = sid;
        return this;
    }

    public SecurityReading For(SecuredKind kind)
    {
        var entries = new List<PermissionEntry>();
        if (_hasList)
        {
            entries.AddRange(_grants.Where(g => !g.Allows).Select(g => Entry(kind, g)));
            entries.Add(new PermissionEntry(System, Allows: true, Mask(kind, Level.Full)));
            entries.Add(new PermissionEntry(Administrators, Allows: true, Mask(kind, Level.Full)));
            entries.AddRange(_grants.Where(g => g.Allows).Select(g => Entry(kind, g)));
        }

        return new SecurityReading(kind, _owner, _hasList, entries);
    }

    private static PermissionEntry Entry(SecuredKind kind, (string Sid, Level Level, bool Allows, bool InheritOnly) grant) =>
        new(grant.Sid, grant.Allows, Mask(kind, grant.Level), grant.InheritOnly);

    /// <summary>The masks Windows itself stores for these levels.</summary>
    private static uint Mask(SecuredKind kind, Level level) => (kind, level) switch
    {
        (SecuredKind.RegistryKey, Level.Read) => 0x20019,
        (SecuredKind.RegistryKey, Level.Add) => 0x2001B,
        (SecuredKind.RegistryKey, Level.AddFolders) => 0x2001D,
        (SecuredKind.RegistryKey, Level.Modify) => 0x3001F,
        (SecuredKind.RegistryKey, Level.Full) => 0xF003F,
        (_, Level.Read) => 0x1200A9,
        (_, Level.Add) => 0x1200AB,
        (_, Level.AddFolders) => 0x1200AD,
        (_, Level.Modify) => 0x1301BF,
        _ => 0x1F01FF,
    };
}
