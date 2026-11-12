using System.Runtime.InteropServices.WindowsRuntime;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media.Imaging;
using Windows.Graphics.Imaging;
using Windows.Storage.Streams;

namespace SecReview.App;

/// <summary>
/// Saves a picture of the window's content as a PNG. Used with <c>--demo</c> to look at every
/// state of the window, and to make documentation pictures, without a real PC's results.
/// </summary>
internal static class Screenshot
{
    public static async Task SaveAsync(UIElement element, string path)
    {
        var bitmap = new RenderTargetBitmap();
        await bitmap.RenderAsync(element);
        IBuffer pixels = await bitmap.GetPixelsAsync();

        using var stream = new InMemoryRandomAccessStream();
        BitmapEncoder encoder = await BitmapEncoder.CreateAsync(BitmapEncoder.PngEncoderId, stream);
        encoder.SetPixelData(
            BitmapPixelFormat.Bgra8,
            BitmapAlphaMode.Premultiplied,
            (uint)bitmap.PixelWidth,
            (uint)bitmap.PixelHeight,
            dpiX: 96,
            dpiY: 96,
            pixels.ToArray());
        await encoder.FlushAsync();

        byte[] png = new byte[stream.Size];
        stream.Seek(0);
        using (var reader = new DataReader(stream))
        {
            await reader.LoadAsync((uint)stream.Size);
            reader.ReadBytes(png);
        }

        // Written to a temporary file first, so a half-written picture is never left behind.
        // Its name is unique, so nothing that already exists is overwritten or removed by it.
        string fullPath = Path.GetFullPath(path);
        string temporary = $"{fullPath}.{Guid.NewGuid():N}.tmp";
        try
        {
            await File.WriteAllBytesAsync(temporary, png);
            File.Move(temporary, fullPath, overwrite: true);
        }
        catch
        {
            TryDelete(temporary);
            throw;
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // The original failure is the one worth reporting.
        }
    }
}
