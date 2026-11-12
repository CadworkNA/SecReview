namespace SecReview.Tray;

/// <summary>
/// SecReview's icon as an .ico file: the shield of <see cref="TrayIconImage"/> at the sizes
/// Windows asks for. The file in the repository (<c>resources/SecReview.ico</c>, used for the
/// programs and the installer) is exactly what this produces; a test holds it to that, so the
/// icon is a picture drawn by reviewed code and not an opaque file.
/// </summary>
public static class IconFile
{
    /// <summary>The sizes in the file: the small ones at every display scale, and the large one for Explorer.</summary>
    public static IReadOnlyList<int> Sizes { get; } = [16, 20, 24, 32, 40, 48, 64, 256];

    private const int FileHeaderSize = 6;
    private const int EntrySize = 16;
    private const int BitmapHeaderSize = 40;

    /// <summary>The file's bytes: the green shield with the tick, at each of <see cref="Sizes"/>.</summary>
    public static byte[] Create()
    {
        byte[][] images = [.. Sizes.Select(Image)];

        using var file = new MemoryStream();
        using var writer = new BinaryWriter(file);
        writer.Write((ushort)0);            // reserved
        writer.Write((ushort)1);            // an icon, not a cursor
        writer.Write((ushort)images.Length);

        int offset = FileHeaderSize + (EntrySize * images.Length);
        for (int index = 0; index < images.Length; index++)
        {
            int size = Sizes[index];
            writer.Write((byte)(size == 256 ? 0 : size)); // width; 0 stands for 256
            writer.Write((byte)(size == 256 ? 0 : size)); // height
            writer.Write((byte)0);          // no palette
            writer.Write((byte)0);          // reserved
            writer.Write((ushort)1);        // planes
            writer.Write((ushort)32);       // bits per pixel
            writer.Write(images[index].Length);
            writer.Write(offset);
            offset += images[index].Length;
        }

        foreach (byte[] image in images)
        {
            writer.Write(image);
        }

        writer.Flush();
        return file.ToArray();
    }

    /// <summary>
    /// One size as the file holds it: a bitmap header, the pixels from the bottom row up with
    /// colours not multiplied by alpha, then a one-bit mask of what is see-through.
    /// </summary>
    private static byte[] Image(int size)
    {
        byte[] drawn = TrayIconImage.Draw(size, TrayState.Fine, darkTaskbar: true);
        int maskStride = ((size + 31) / 32) * 4;

        using var image = new MemoryStream();
        using var writer = new BinaryWriter(image);
        writer.Write(BitmapHeaderSize);
        writer.Write(size);
        writer.Write(size * 2);             // colour rows and mask rows together
        writer.Write((ushort)1);
        writer.Write((ushort)32);
        writer.Write(0);                    // not compressed
        writer.Write(size * size * 4);
        writer.Write(0);
        writer.Write(0);
        writer.Write(0);
        writer.Write(0);

        for (int y = size - 1; y >= 0; y--)
        {
            for (int x = 0; x < size; x++)
            {
                int at = ((y * size) + x) * 4;
                byte alpha = drawn[at + 3];
                writer.Write(Straight(drawn[at], alpha));
                writer.Write(Straight(drawn[at + 1], alpha));
                writer.Write(Straight(drawn[at + 2], alpha));
                writer.Write(alpha);
            }
        }

        for (int y = size - 1; y >= 0; y--)
        {
            byte[] row = new byte[maskStride];
            for (int x = 0; x < size; x++)
            {
                if (drawn[(((y * size) + x) * 4) + 3] == 0)
                {
                    row[x / 8] |= (byte)(0x80 >> (x % 8));
                }
            }

            writer.Write(row);
        }

        writer.Flush();
        return image.ToArray();
    }

    /// <summary>A colour as it was before it was multiplied by its alpha.</summary>
    private static byte Straight(byte value, byte alpha) => alpha == 0 ? (byte)0 : (byte)Math.Min(255, ((value * 255) + (alpha / 2)) / alpha);
}
