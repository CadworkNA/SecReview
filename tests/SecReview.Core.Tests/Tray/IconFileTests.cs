using System.Buffers.Binary;
using SecReview.Tray;

namespace SecReview.Tests.Tray;

[TestClass]
public sealed class IconFileTests
{
    [TestMethod]
    public void TheFile_HoldsEverySize_EachWhereItsEntrySays()
    {
        byte[] file = IconFile.Create();

        Assert.AreEqual(0, BinaryPrimitives.ReadUInt16LittleEndian(file));
        Assert.AreEqual(1, BinaryPrimitives.ReadUInt16LittleEndian(file.AsSpan(2)), "an icon");
        Assert.AreEqual(IconFile.Sizes.Count, BinaryPrimitives.ReadUInt16LittleEndian(file.AsSpan(4)));

        int expectedOffset = 6 + (16 * IconFile.Sizes.Count);
        for (int index = 0; index < IconFile.Sizes.Count; index++)
        {
            int size = IconFile.Sizes[index];
            ReadOnlySpan<byte> entry = file.AsSpan(6 + (16 * index), 16);
            Assert.AreEqual(size == 256 ? 0 : size, entry[0], "width");
            Assert.AreEqual(size == 256 ? 0 : size, entry[1], "height");
            Assert.AreEqual(32, BinaryPrimitives.ReadUInt16LittleEndian(entry[6..]), "bits per pixel");

            int length = BinaryPrimitives.ReadInt32LittleEndian(entry[8..]);
            int offset = BinaryPrimitives.ReadInt32LittleEndian(entry[12..]);
            Assert.AreEqual(expectedOffset, offset);
            Assert.AreEqual(40 + (size * size * 4) + (size * ((size + 31) / 32) * 4), length, $"header, pixels and mask at {size}");

            ReadOnlySpan<byte> image = file.AsSpan(offset, length);
            Assert.AreEqual(40, BinaryPrimitives.ReadInt32LittleEndian(image));
            Assert.AreEqual(size, BinaryPrimitives.ReadInt32LittleEndian(image[4..]));
            Assert.AreEqual(size * 2, BinaryPrimitives.ReadInt32LittleEndian(image[8..]), "pixels and mask");
            expectedOffset += length;
        }

        Assert.AreEqual(expectedOffset, file.Length);
    }

    [TestMethod]
    public void ThePixels_AreTheGreenShield_BottomRowFirst_WithColoursNotMultiplied()
    {
        const int Size = 32;
        byte[] file = IconFile.Create();
        int index = IconFile.Sizes.ToList().IndexOf(Size);
        int offset = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(6 + (16 * index) + 12));
        ReadOnlySpan<byte> pixels = file.AsSpan(offset + 40, Size * Size * 4);
        ReadOnlySpan<byte> mask = file.AsSpan(offset + 40 + (Size * Size * 4), Size * 4);
        (byte r, byte g, byte b) = TrayIconImage.Colour(TrayState.Fine, darkTaskbar: true);

        // Row 0 of the file is the bottom of the picture: its corners are clear and masked out.
        Assert.AreEqual(0, pixels[3], "bottom left is see-through");
        Assert.AreEqual(0x80, mask[0] & 0x80, "and masked");

        // Near the top of the picture, inside the shield: the colour itself, solid, not masked.
        int row = Size - 1 - (Size / 6);
        int at = ((row * Size) + (Size / 2)) * 4;
        Assert.AreEqual((b, g, r, (byte)255), (pixels[at], pixels[at + 1], pixels[at + 2], pixels[at + 3]));
        Assert.AreEqual(0, mask[(row * 4) + (Size / 2 / 8)] & (0x80 >> (Size / 2 % 8)));

        // On the soft edge, colours are whole again (not darkened by their alpha).
        bool sawEdge = false;
        for (int pixel = 0; pixel < Size * Size; pixel++)
        {
            byte alpha = pixels[(pixel * 4) + 3];
            if (alpha is > 40 and < 215 && pixels[(pixel * 4) + 1] is > 0)
            {
                sawEdge = true;
                Assert.IsTrue(Math.Abs(pixels[(pixel * 4) + 1] - g) <= 6 || pixels[(pixel * 4) + 1] > g, $"pixel {pixel}: green {pixels[(pixel * 4) + 1]} at alpha {alpha}");
            }
        }

        Assert.IsTrue(sawEdge);
    }

    [TestMethod]
    public void TheIconInTheRepository_IsExactlyWhatTheCodeDraws()
    {
        byte[] drawn = IconFile.Create();

        using Stream? stored = typeof(IconFileTests).Assembly.GetManifestResourceStream("SecReview.ico");
        byte[] kept = [];
        if (stored is not null)
        {
            kept = new byte[stored.Length];
            stored.ReadExactly(kept);
        }

        if (!drawn.AsSpan().SequenceEqual(kept))
        {
            // What the file should be, left where a developer can pick it up.
            string expected = Path.Combine(AppContext.BaseDirectory, "SecReview.expected.ico");
            File.WriteAllBytes(expected, drawn);
            Assert.Fail($"resources/SecReview.ico is not what IconFile.Create draws. Replace it with {expected}.");
        }
    }
}
