using SecReview.Checks.BuiltIn.Programs;
using SecReview.Probing;
using SecReview.Tests.Fakes;

namespace SecReview.Tests.Checks.Programs;

[TestClass]
public sealed class AccessRulesTests
{
    private const uint FolderRead = 0x1200A9;
    private const uint FolderModify = 0x1301BF;
    private const uint Full = 0x1F01FF;

    private static SecurityReading Folder(params PermissionEntry[] entries) =>
        new(SecuredKind.Folder, FakeAccess.Administrators, HasList: true, entries);

    private static PermissionEntry Allow(string sid, uint rights, bool inheritOnly = false) => new(sid, Allows: true, rights, inheritOnly);

    private static PermissionEntry Deny(string sid, uint rights) => new(sid, Allows: false, rights);

    [TestMethod]
    public void TheWindowsDefaultForPrograms_LetsNoStandardUserChangeAnything()
    {
        foreach (SecuredKind kind in Enum.GetValues<SecuredKind>())
        {
            ChangeAccess access = AccessRules.Evaluate(FakeAccess.Protected.For(kind));

            Assert.AreEqual(ChangeRights.None, access.Rights, kind.ToString());
            Assert.AreEqual(0, access.Groups.Count);
            Assert.AreEqual(0, access.OtherAccounts);
            Assert.AreEqual(string.Empty, access.Who());
        }
    }

    [TestMethod]
    public void ModifyForUsers_OnAFolder_IsEveryWayOfChangingItButItsPermissions()
    {
        ChangeAccess access = AccessRules.Evaluate(FakeAccess.UsersModify.For(SecuredKind.Folder));

        Assert.AreEqual("Users", access.Who());
        Assert.AreEqual(ChangeRights.AddFile | ChangeRights.AddSubfolder | ChangeRights.Delete, access.Rights);
        Assert.IsFalse(access.Has(ChangeRights.Control));
    }

    [TestMethod]
    public void ModifyForUsers_OnAFile_IsWritingAndDeleting()
    {
        ChangeAccess access = AccessRules.Evaluate(FakeAccess.UsersModify.For(SecuredKind.File));

        Assert.AreEqual(ChangeRights.WriteContent | ChangeRights.Delete, access.Rights);
    }

    [TestMethod]
    public void FullControl_IsEverything_AndTheGroupsAreNamedMostGeneralFirst()
    {
        ChangeAccess access = AccessRules.Evaluate(
            FakeAccess.Protected.Allow(FakeAccess.Users, FakeAccess.Level.Modify).Allow(FakeAccess.AuthenticatedUsers, FakeAccess.Level.Full).For(SecuredKind.Folder));

        Assert.AreEqual("Authenticated Users and Users", access.Who());
        Assert.AreEqual(ChangeRights.All & ~ChangeRights.WriteContent, access.Rights);
        Assert.AreEqual("Authenticated Users", access.Who(ChangeRights.Control), "only the groups holding the rights asked about");
    }

    [TestMethod]
    public void OnARegistryKey_SettingValuesAndCreatingKeys_AreToldApart()
    {
        Assert.AreEqual(
            ChangeRights.WriteContent,
            AccessRules.Evaluate(FakeAccess.UsersAdd.For(SecuredKind.RegistryKey)).Rights);
        Assert.AreEqual(
            ChangeRights.AddSubfolder,
            AccessRules.Evaluate(FakeAccess.Protected.Allow(FakeAccess.Users, FakeAccess.Level.AddFolders).For(SecuredKind.RegistryKey)).Rights);
        Assert.AreEqual(
            ChangeRights.AddSubfolder,
            AccessRules.Evaluate(new SecurityReading(SecuredKind.RegistryKey, FakeAccess.System, true, [Allow(FakeAccess.Users, 0x20)])).Rights,
            "creating a link in a key redirects it");
    }

    [TestMethod]
    public void WhatWindowsGivesUsersOnADrivesTopFolder_IsCreatingFoldersOnly()
    {
        ChangeAccess access = AccessRules.Evaluate(Folder(
            Allow(FakeAccess.Administrators, Full),
            Allow(FakeAccess.Users, FolderRead),
            Allow(FakeAccess.AuthenticatedUsers, 0x4),
            Allow(FakeAccess.AuthenticatedUsers, 0x10000000, inheritOnly: true)));

        Assert.AreEqual("Authenticated Users", access.Who());
        Assert.AreEqual(ChangeRights.AddSubfolder, access.Rights, "the entry that is only handed down does not apply to the folder itself");
    }

    [TestMethod]
    [DataRow(0x10000000u, (int)(ChangeRights.All & ~ChangeRights.WriteContent), DisplayName = "generic all")]
    [DataRow(0x40000000u, (int)(ChangeRights.AddFile | ChangeRights.AddSubfolder), DisplayName = "generic write")]
    [DataRow(0x80000000u, (int)(ChangeRights.None), DisplayName = "generic read")]
    [DataRow(0x20000000u, (int)(ChangeRights.None), DisplayName = "generic execute")]
    public void GenericRights_CountAsTheRightsTheyStandFor(uint mask, int expected)
    {
        Assert.AreEqual((ChangeRights)expected, AccessRules.Evaluate(Folder(Allow(FakeAccess.Users, mask))).Rights);
    }

    [TestMethod]
    public void ADenyBeforeTheAllow_ForTheSameGroupOrOneAllItsMembersAreIn_TakesTheRightAway()
    {
        Assert.AreEqual(
            ChangeRights.None,
            AccessRules.Evaluate(Folder(Deny(FakeAccess.Users, FolderModify), Allow(FakeAccess.Users, FolderModify))).Rights);
        Assert.AreEqual(
            ChangeRights.None,
            AccessRules.Evaluate(Folder(Deny(FakeAccess.Everyone, FolderModify), Allow(FakeAccess.Users, FolderModify))).Rights,
            "every member of Users is in Everyone");
        Assert.AreEqual(
            ChangeRights.Delete,
            AccessRules.Evaluate(Folder(Deny(FakeAccess.Users, 0x6), Allow(FakeAccess.Users, FolderModify))).Rights,
            "only the denied rights go");
    }

    [TestMethod]
    public void ADenyThatDoesNotCoverEveryMember_OrComesTooLate_ChangesNothing()
    {
        ChangeRights modify = ChangeRights.AddFile | ChangeRights.AddSubfolder | ChangeRights.Delete;

        Assert.AreEqual(
            modify,
            AccessRules.Evaluate(Folder(Deny("S-1-5-32-546", FolderModify), Allow(FakeAccess.Users, FolderModify))).Rights,
            "a deny for Guests does not stop Users");
        Assert.AreEqual(
            modify,
            AccessRules.Evaluate(Folder(Deny(FakeAccess.Users, FolderModify), Allow(FakeAccess.Everyone, FolderModify))).Rights,
            "not everyone is in Users");
        Assert.AreEqual(
            modify,
            AccessRules.Evaluate(Folder(Allow(FakeAccess.Users, FolderModify), Deny(FakeAccess.Users, FolderModify))).Rights,
            "Windows stops at the first entry that decides");
        Assert.AreEqual(
            modify,
            AccessRules.Evaluate(Folder(new PermissionEntry(FakeAccess.Users, Allows: false, FolderModify, Conditional: true), Allow(FakeAccess.Users, FolderModify))).Rights,
            "a deny under a condition may not apply");
    }

    [TestMethod]
    public void NoListAtAll_IsEveryoneEverything_AndAnEmptyListIsNobody()
    {
        ChangeAccess none = AccessRules.Evaluate(FakeAccess.NoList.For(SecuredKind.File));
        ChangeAccess empty = AccessRules.Evaluate(new SecurityReading(SecuredKind.File, FakeAccess.Administrators, HasList: true, []));

        Assert.AreEqual("Everyone", none.Who());
        Assert.AreEqual(ChangeRights.All, none.Rights);
        Assert.AreEqual(ChangeRights.None, empty.Rights);
    }

    [TestMethod]
    public void AGroupOfStandardUsersThatOwnsIt_CanRewriteItsPermissions_UnlessOwnerRightsSayOtherwise()
    {
        SecurityReading owned = FakeAccess.Protected.OwnedBy(FakeAccess.Users).For(SecuredKind.Folder);
        SecurityReading limited = owned with { Entries = [.. owned.Entries, Allow("S-1-3-4", FolderRead)] };
        SecurityReading stillFull = owned with { Entries = [.. owned.Entries, Allow("S-1-3-4", Full)] };

        Assert.AreEqual(ChangeRights.ChangePermissions, AccessRules.Evaluate(owned).Rights);
        Assert.AreEqual("Users", AccessRules.Evaluate(owned).Who());
        Assert.AreEqual(ChangeRights.None, AccessRules.Evaluate(limited).Rights);
        Assert.IsTrue(AccessRules.Evaluate(stillFull).Has(ChangeRights.ChangePermissions));
    }

    [TestMethod]
    public void NamedAccounts_AreCounted_NotJudged_AndAdministratorsAndServicesAreNeither()
    {
        ChangeAccess access = AccessRules.Evaluate(Folder(
            Allow(FakeAccess.SomeAccount, Full),
            Allow(FakeAccess.SomeAccount, FolderModify),
            Allow("S-1-5-21-1111111111-2222222222-3333333333-1002", FolderRead),
            Allow("S-1-12-1-1-2-3-4", FolderModify),
            Allow("S-1-5-21-1111111111-2222222222-3333333333-500", Full),
            Allow("S-1-5-21-1111111111-2222222222-3333333333-512", Full),
            Allow(FakeAccess.TrustedInstaller, Full),
            Allow("S-1-15-2-1", Full),
            Allow("S-1-5-32-544", Full)));

        Assert.AreEqual(0, access.Groups.Count);
        Assert.AreEqual(2, access.OtherAccounts, "two accounts can change it; one only reads");
    }

    [TestMethod]
    [DataRow("S-1-5-21-1111111111-2222222222-3333333333-513", "Domain Users")]
    [DataRow("S-1-5-21-1111111111-2222222222-3333333333-501", "Guest")]
    [DataRow("S-1-5-4", "Interactive")]
    [DataRow("S-1-5-32-555", "Remote Desktop Users")]
    public void OtherGroupsOfOrdinaryAccounts_AreNamed(string sid, string name)
    {
        ChangeAccess access = AccessRules.Evaluate(Folder(Allow(sid, FolderModify)));

        Assert.AreEqual(name, access.Who());
        Assert.AreEqual(0, access.OtherAccounts);
    }

    [TestMethod]
    public void AnyList_IsReadWithoutFailing()
    {
        var random = new Random(20261112);
        string[] sids = [FakeAccess.Everyone, FakeAccess.Users, FakeAccess.SomeAccount, "S-1-3-4", "", "not a sid", "S-1-5-21-513"];
        for (int round = 0; round < 2000; round++)
        {
            PermissionEntry[] entries =
            [
                .. Enumerable.Range(0, random.Next(0, 8)).Select(_ => new PermissionEntry(
                    sids[random.Next(sids.Length)], random.Next(2) == 0, (uint)random.NextInt64(0, 1L << 32), random.Next(3) == 0, random.Next(5) == 0)),
            ];
            var reading = new SecurityReading(
                (SecuredKind)random.Next(3), sids[random.Next(sids.Length)], random.Next(10) != 0, entries);

            ChangeAccess access = AccessRules.Evaluate(reading);

            Assert.IsTrue(access.OtherAccounts >= 0);
            Assert.AreEqual(access.Rights != ChangeRights.None, access.Who().Length > 0);
        }
    }
}
