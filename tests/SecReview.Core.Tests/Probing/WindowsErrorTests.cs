using SecReview.Probing;
using SecReview.Probing.Windows;

namespace SecReview.Tests.Probing;

[TestClass]
public sealed class WindowsErrorTests
{
    private const string What = "Reading the thing";

    [TestMethod]
    [DataRow(5, DisplayName = "ERROR_ACCESS_DENIED")]
    [DataRow(1314, DisplayName = "ERROR_PRIVILEGE_NOT_HELD")]
    public void Win32AccessErrors_MeanAccessDenied(int error)
    {
        Assert.AreEqual(ProbeStatus.AccessDenied, WindowsError.FromWin32(error, What).Status);
    }

    [TestMethod]
    public void Win32FileNotFound_MeansNotFound()
    {
        Assert.AreEqual(ProbeStatus.NotFound, WindowsError.FromWin32(2, What).Status);
    }

    [TestMethod]
    public void OtherWin32Error_IsAFailureThatNamesTheOperationAndCode()
    {
        ProbeFailure failure = WindowsError.FromWin32(1722, What);

        Assert.AreEqual(ProbeStatus.Failed, failure.Status);
        StringAssert.StartsWith(failure.Detail, What);
        StringAssert.Contains(failure.Detail, "0x000006BA");
    }

    [TestMethod]
    [DataRow(unchecked((int)0x80070005), DisplayName = "E_ACCESSDENIED")]
    [DataRow(unchecked((int)0x80070522), DisplayName = "privilege not held")]
    public void HResultAccessErrors_MeanAccessDenied(int hresult)
    {
        Assert.AreEqual(ProbeStatus.AccessDenied, WindowsError.FromHResult(hresult, What).Status);
    }

    [TestMethod]
    [DataRow(unchecked((int)0x80040154), DisplayName = "class not registered")]
    [DataRow(unchecked((int)0x80004002), DisplayName = "no such interface")]
    public void MissingComClass_MeansNotSupported(int hresult)
    {
        ProbeFailure failure = WindowsError.FromHResult(hresult, What);

        Assert.AreEqual(ProbeStatus.NotSupported, failure.Status);
        StringAssert.Contains(failure.Detail, What);
    }

    [TestMethod]
    public void UnauthorizedAccessException_MeansAccessDenied()
    {
        var failure = WindowsError.FromException(new UnauthorizedAccessException(), What);

        Assert.AreEqual(ProbeStatus.AccessDenied, failure.Status);
    }

    [TestMethod]
    public void UnexpectedException_IsAFailure_NotAThrow()
    {
        var failure = WindowsError.FromException(new InvalidOperationException("boom"), What);

        Assert.AreEqual(ProbeStatus.Failed, failure.Status);
        StringAssert.StartsWith(failure.Detail, What);
    }
}
