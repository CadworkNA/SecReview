using System.Collections.ObjectModel;
using WinRT;

// Tells the WinRT interop generator which .NET collection types are handed to WinUI controls as
// plain objects (through data binding). Without this the control receives something it cannot
// enumerate and fails with "not a supported vector": with Native AOT nothing can be worked out
// at run time, so every such type has to be named at build time.
[assembly: GeneratedWinRTExposedExternalType(typeof(ObservableCollection<object>))]
[assembly: GeneratedWinRTExposedExternalType(typeof(List<object>))]
