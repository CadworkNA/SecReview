using System.Collections.ObjectModel;
using SecReview.Scanning;

namespace SecReview.Tests.Scanning;

[TestClass]
public sealed class ListSyncTests
{
    private static readonly object[] Items = [.. Enumerable.Range(0, 12).Select(i => (object)$"item {i}")];

    private static List<object> Pick(params int[] indexes) => [.. indexes.Select(i => Items[i])];

    private static void AssertSame(List<object> wanted, ObservableCollection<object> current)
    {
        Assert.AreEqual(wanted.Count, current.Count);
        for (int i = 0; i < wanted.Count; i++)
        {
            Assert.AreSame(wanted[i], current[i], $"position {i}");
        }
    }

    [TestMethod]
    public void AListThatIsAlreadyRight_IsNotTouched()
    {
        var current = new ObservableCollection<object>(Pick(0, 1, 2));
        int notifications = 0;
        current.CollectionChanged += (_, _) => notifications++;

        Assert.AreEqual(0, ListSync.Apply(current, Pick(0, 1, 2)));
        Assert.AreEqual(0, notifications);
    }

    [TestMethod]
    public void OneChangedRow_IsTheOnlyOneTouched()
    {
        var current = new ObservableCollection<object>(Pick(0, 1, 2, 3, 4));
        var touched = new List<object>();
        current.CollectionChanged += (_, e) =>
        {
            touched.AddRange((e.OldItems ?? Array.Empty<object>()).Cast<object>());
            touched.AddRange((e.NewItems ?? Array.Empty<object>()).Cast<object>());
        };

        // Row 2 has a new result: a new object takes its place.
        List<object> wanted = Pick(0, 1, 9, 3, 4);
        ListSync.Apply(current, wanted);

        AssertSame(wanted, current);
        CollectionAssert.AreEquivalent(new[] { Items[2], Items[9] }, touched);
    }

    [TestMethod]
    [DataRow(new[] { 0, 1, 2 }, new int[0], DisplayName = "everything goes")]
    [DataRow(new int[0], new[] { 0, 1, 2 }, DisplayName = "everything is new")]
    [DataRow(new[] { 0, 1, 2 }, new[] { 2, 1, 0 }, DisplayName = "reversed")]
    [DataRow(new[] { 0, 1, 2, 3 }, new[] { 3, 0, 1, 2 }, DisplayName = "the last comes first")]
    [DataRow(new[] { 0, 1, 2, 3 }, new[] { 1, 2, 3, 0 }, DisplayName = "the first goes last")]
    [DataRow(new[] { 0, 1, 2 }, new[] { 0, 5, 1, 6, 2 }, DisplayName = "new ones in between")]
    [DataRow(new[] { 0, 1, 2, 3, 4 }, new[] { 1, 3 }, DisplayName = "some go")]
    [DataRow(new[] { 0, 1 }, new[] { 7, 8, 9 }, DisplayName = "nothing in common")]
    public void AnyListBecomesAnyOther(int[] before, int[] after)
    {
        var current = new ObservableCollection<object>(Pick(before));
        List<object> wanted = Pick(after);

        ListSync.Apply(current, wanted);

        AssertSame(wanted, current);
    }

    [TestMethod]
    public void RandomLists_AlwaysEndUpEqual_AndWhatStaysIsNeverTakenOutWhenTheOrderHolds()
    {
        var random = new Random(20261112);
        for (int round = 0; round < 2000; round++)
        {
            List<object> before = [.. Items.Where(_ => random.Next(2) == 0)];
            List<object> after = [.. Items.Where(_ => random.Next(2) == 0)];
            if (random.Next(4) == 0)
            {
                after.Reverse();
            }

            var current = new ObservableCollection<object>(before);
            var removed = new List<object>();
            current.CollectionChanged += (_, e) => removed.AddRange((e.OldItems ?? Array.Empty<object>()).Cast<object>());

            ListSync.Apply(current, after);

            AssertSame(after, current);
            bool sameOrder = after.Select(item => Array.IndexOf(Items, item)).SequenceEqual(after.Select(item => Array.IndexOf(Items, item)).Order());
            if (sameOrder)
            {
                Assert.IsFalse(removed.Any(after.Contains), $"round {round}: a row that stays was taken off the screen");
            }
        }
    }
}
