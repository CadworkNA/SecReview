using SecReview.Tray;

namespace SecReview.Tests.Tray;

[TestClass]
public sealed class TrayIconImageTests
{
    private static (int B, int G, int R, int A) Pixel(byte[] pixels, int size, int x, int y)
    {
        int at = ((y * size) + x) * 4;
        return (pixels[at], pixels[at + 1], pixels[at + 2], pixels[at + 3]);
    }

    [TestMethod]
    [DataRow(16)]
    [DataRow(20)]
    [DataRow(24)]
    [DataRow(32)]
    [DataRow(48)]
    public void AShield_SolidInTheMiddle_ClearInTheCorners_AtEverySize(int size)
    {
        foreach (TrayState state in Enum.GetValues<TrayState>())
        {
            byte[] pixels = TrayIconImage.Draw(size, state, darkTaskbar: true);

            Assert.AreEqual(size * size * 4, pixels.Length);
            Assert.AreEqual(0, Pixel(pixels, size, 0, 0).A, "top left");
            Assert.AreEqual(0, Pixel(pixels, size, size - 1, 0).A, "top right");
            Assert.AreEqual(0, Pixel(pixels, size, 0, size - 1).A, "bottom left");
            Assert.AreEqual(0, Pixel(pixels, size, size - 1, size - 1).A, "bottom right");
            Assert.AreEqual(255, Pixel(pixels, size, size / 2, size / 5).A, "inside the shield, above the mark");

            // Colours are multiplied by alpha: no channel may exceed it.
            for (int at = 0; at < pixels.Length; at += 4)
            {
                Assert.IsTrue(pixels[at] <= pixels[at + 3] && pixels[at + 1] <= pixels[at + 3] && pixels[at + 2] <= pixels[at + 3], $"pixel {at / 4}");
            }

            int covered = Enumerable.Range(0, size * size).Count(i => pixels[(i * 4) + 3] > 128);
            Assert.IsTrue(covered > size * size * 0.45 && covered < size * size * 0.80, $"{state} at {size}: {covered} pixels covered");
        }
    }

    [TestMethod]
    public void EachState_HasItsOwnColour_AndAWhiteMark()
    {
        const int Size = 32;
        foreach (TrayState state in Enum.GetValues<TrayState>())
        {
            byte[] pixels = TrayIconImage.Draw(Size, state, darkTaskbar: false);
            (byte r, byte g, byte b) = TrayIconImage.Colour(state, darkTaskbar: false);

            // Just under the peak, away from any mark: the state's colour.
            (int B, int G, int R, int A) body = Pixel(pixels, Size, Size / 2, Size / 6);
            Assert.AreEqual((b, g, r, 255), (body.B, body.G, body.R, body.A), state.ToString());

            int white = Enumerable.Range(0, Size * Size).Count(i => pixels[i * 4] == 255 && pixels[(i * 4) + 1] == 255 && pixels[(i * 4) + 2] == 255);
            Assert.IsTrue(white >= 12, $"{state}: only {white} white pixels");
        }

        Assert.AreNotEqual(TrayIconImage.Colour(TrayState.Fine, false), TrayIconImage.Colour(TrayState.NeedsAttention, false));
        Assert.AreNotEqual(TrayIconImage.Colour(TrayState.Fine, false), TrayIconImage.Colour(TrayState.Unknown, false));
        (byte R, byte G, byte B) green = TrayIconImage.Colour(TrayState.Fine, true);
        Assert.IsTrue(green.G > green.R && green.G > green.B, "fine is green");
        (byte R, byte G, byte B) orange = TrayIconImage.Colour(TrayState.NeedsAttention, true);
        Assert.IsTrue(orange.R > orange.G && orange.G > orange.B, "attention is orange");
    }

    [TestMethod]
    public void TheMarks_AreToldApart()
    {
        const int Size = 32;
        static bool White(byte[] pixels, int x, int y) => pixels[((y * Size) + x) * 4] == 255 && pixels[(((y * Size) + x) * 4) + 1] == 255;

        byte[] attention = TrayIconImage.Draw(Size, TrayState.NeedsAttention, true);
        byte[] paused = TrayIconImage.Draw(Size, TrayState.Snoozed, true);
        byte[] unknown = TrayIconImage.Draw(Size, TrayState.Unknown, true);
        byte[] fine = TrayIconImage.Draw(Size, TrayState.Fine, true);

        // The exclamation mark: white down the middle, and its dot below.
        Assert.IsTrue(White(attention, 16, 13) && White(attention, 16, 23));
        Assert.IsFalse(White(attention, 16, 20), "the gap between the bar and the dot");

        // The pause sign: two bars with the middle clear.
        Assert.IsTrue(White(paused, 13, 16) && White(paused, 19, 16));
        Assert.IsFalse(White(paused, 16, 16));

        // The dash: white across the middle, not above it.
        Assert.IsTrue(White(unknown, 13, 16) && White(unknown, 19, 16) && White(unknown, 16, 16));
        Assert.IsFalse(White(unknown, 16, 11));

        // The tick: its corner low and left of centre, its long arm up to the right.
        Assert.IsTrue(White(fine, 14, 21) && White(fine, 21, 13));
        Assert.IsFalse(White(fine, 10, 11));
    }

    [TestMethod]
    public void GreyFollowsTheTaskbar_SoItShowsOnBoth()
    {
        (byte R, byte G, byte B) onDark = TrayIconImage.Colour(TrayState.Unknown, darkTaskbar: true);
        (byte R, byte G, byte B) onLight = TrayIconImage.Colour(TrayState.Unknown, darkTaskbar: false);

        Assert.IsTrue(onDark.R > onLight.R, "lighter on a dark taskbar");
        Assert.AreEqual(TrayIconImage.Colour(TrayState.Snoozed, true), onDark);
        Assert.AreEqual(TrayIconImage.Colour(TrayState.Fine, true), TrayIconImage.Colour(TrayState.Fine, false), "green and orange show on both");
    }

    [TestMethod]
    public void ASizeWindowsWouldNotAskFor_IsRefused()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => TrayIconImage.Draw(8, TrayState.Fine, true));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => TrayIconImage.Draw(1024, TrayState.Fine, true));
    }
}
