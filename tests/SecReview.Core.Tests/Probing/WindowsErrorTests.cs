using System.ComponentModel;
using System.Runtime.InteropServices;
using SecReview.Probing;
using SecReview.Probing.Windows;

namespace SecReview.Tests.Probing;

[TestClass]
public sealed class WindowsErrorTests
{
    private const string What = "Reading the thing";
    private const int ENoInterface = unchecked((int)0x80004002);

    [TestMethod]
    [DataRow(5, DisplayName = "ERROR_ACCESS_DENIED")]
    [DataRow(1314, DisplayName = "ERROR_PRIVILEGE_NOT_HELD")]
    public void Win32AccessErrors_MeanAccessDenied(int error)
    {
        Assert.AreEqual(ProbeStatus.AccessDenied, WindowsError.FromWin32(error, What).Status);
    }

    [TestMethod]
    [DataRow(2, DisplayName = "ERROR_FILE_NOT_FOUND")]
    [DataRow(3, DisplayName = "ERROR_PATH_NOT_FOUND")]
    public void Win32NotFoundErrors_MeanNotFound(int error)
    {
        Assert.AreEqual(ProbeStatus.NotFound, WindowsError.FromWin32(error, What).Status);
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
    [DataRow(unchecked((int)0x80070005), ProbeStatus.AccessDenied, DisplayName = "E_ACCESSDENIED")]
    [DataRow(unchecked((int)0x80070522), ProbeStatus.AccessDenied, DisplayName = "privilege not held")]
    [DataRow(unchecked((int)0x80070002), ProbeStatus.NotFound, DisplayName = "file not found")]
    public void HResultWrappingAWin32Error_GetsTheSameStatusAsThatError(int hresult, ProbeStatus expected)
    {
        Assert.AreEqual(expected, WindowsError.FromHResult(hresult, What).Status);
    }

    [TestMethod]
    public void HResultWrappingAnotherWin32Error_IsAFailureThatShowsTheFullCode()
    {
        ProbeFailure failure = WindowsError.FromHResult(unchecked((int)0x800706BA), What);

        Assert.AreEqual(ProbeStatus.Failed, failure.Status);
        StringAssert.Contains(failure.Detail, "0x800706BA");
    }

    [TestMethod]
    [DataRow(unchecked((int)0x80040154), DisplayName = "class not registered")]
    [DataRow(ENoInterface, DisplayName = "no such interface")]
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
    public void ComExceptionForAMissingClass_MeansNotSupported()
    {
        // What a generated COM wrapper throws for "class not registered".
        Exception? exception = Marshal.GetExceptionForHR(unchecked((int)0x80040154));
        Assert.IsInstanceOfType<COMException>(exception);

        var failure = WindowsError.FromException(exception, What);

        Assert.AreEqual(ProbeStatus.NotSupported, failure.Status);
    }

    [TestMethod]
    public void FileNotFoundThrownForAFailedCall_MeansNotFound()
    {
        // The runtime turns "file not found" from a Windows call into this exception type.
        Exception? exception = Marshal.GetExceptionForHR(unchecked((int)0x80070002));
        Assert.IsInstanceOfType<FileNotFoundException>(exception);

        var failure = WindowsError.FromException(exception, What);

        Assert.AreEqual(ProbeStatus.NotFound, failure.Status);
    }

    [TestMethod]
    public void Win32ExceptionForAccessDenied_MeansAccessDenied()
    {
        var failure = WindowsError.FromException(new Win32Exception(5), What);

        Assert.AreEqual(ProbeStatus.AccessDenied, failure.Status);
    }

    [TestMethod]
    public void InvalidCastException_IsAFailure_NotMistakenForNotSupported()
    {
        // InvalidCastException carries the same code as COM's "no such interface". A defect in
        // a probe must never be reported as an edition limitation.
        var exception = new InvalidCastException("wrong type");
        Assert.AreEqual(ENoInterface, exception.HResult);

        var failure = WindowsError.FromException(exception, What);

        Assert.AreEqual(ProbeStatus.Failed, failure.Status);
    }

    [TestMethod]
    public void UnexpectedException_IsAFailureThatKeepsTheCause()
    {
        var failure = WindowsError.FromException(new InvalidOperationException("boom"), What);

        Assert.AreEqual(ProbeStatus.Failed, failure.Status);
        StringAssert.StartsWith(failure.Detail, What);
        StringAssert.Contains(failure.Detail, "InvalidOperationException");
        StringAssert.Contains(failure.Detail, "boom");
    }
}
