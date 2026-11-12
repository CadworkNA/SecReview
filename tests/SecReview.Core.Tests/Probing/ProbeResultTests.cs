using SecReview.Probing;

namespace SecReview.Tests.Probing;

[TestClass]
public sealed class ProbeResultTests
{
    [TestMethod]
    public void Ok_CarriesTheValue()
    {
        var result = ProbeResult<int>.Ok(42);

        Assert.IsTrue(result.IsOk);
        Assert.AreEqual(ProbeStatus.Ok, result.Status);
        Assert.AreEqual(42, result.Value);
        Assert.IsNull(result.Detail);
    }

    [TestMethod]
    public void Failure_ConvertsToAnyResultType_AndIsNeverOk()
    {
        ProbeResult<string> result = ProbeFailure.AccessDenied();

        Assert.IsFalse(result.IsOk);
        Assert.AreEqual(ProbeStatus.AccessDenied, result.Status);
        Assert.IsNull(result.Value);
    }

    [TestMethod]
    public void Failure_KeepsItsDetail()
    {
        ProbeResult<int> result = ProbeFailure.Failed("Reading X failed.");

        Assert.AreEqual(ProbeStatus.Failed, result.Status);
        Assert.AreEqual("Reading X failed.", result.Detail);
    }

    [TestMethod]
    public void ToFailure_RetypesAFailure()
    {
        ProbeResult<int> first = ProbeFailure.NotSupported("Not on this edition.");

        ProbeResult<string> second = first.ToFailure();

        Assert.AreEqual(ProbeStatus.NotSupported, second.Status);
        Assert.AreEqual("Not on this edition.", second.Detail);
    }

    [TestMethod]
    public void ToFailure_OnSuccess_Throws()
    {
        var result = ProbeResult<int>.Ok(1);

        Assert.ThrowsExactly<InvalidOperationException>(() => result.ToFailure());
    }

    [TestMethod]
    public void DefaultResult_IsAFailure_NeverASuccess()
    {
        // A result nobody filled in (default struct, uninitialised field) must not read as "ok".
        ProbeResult<string> unset = default;

        Assert.IsFalse(unset.IsOk);
        Assert.AreEqual(ProbeStatus.Failed, unset.Status);
    }
}
