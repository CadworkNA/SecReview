namespace SecReview.Tests;

[TestClass]
public sealed class ProductInfoTests
{
    [TestMethod]
    [DataRow("1.2.3+0e66df0", "1.2.3")]
    [DataRow("1.2.3", "1.2.3")]
    [DataRow("0.0.0-dev+abc", "0.0.0-dev")]
    [DataRow(null, "0.0.0")]
    [DataRow("  ", "0.0.0")]
    public void StripBuildMetadata_RemovesCommitSuffix(string? informational, string expected)
    {
        Assert.AreEqual(expected, ProductInfo.StripBuildMetadata(informational));
    }

    [TestMethod]
    public void Version_HasNoBuildMetadata()
    {
        Assert.IsFalse(ProductInfo.Version.Contains('+', StringComparison.Ordinal));
        Assert.IsFalse(string.IsNullOrWhiteSpace(ProductInfo.Version));
    }
}
