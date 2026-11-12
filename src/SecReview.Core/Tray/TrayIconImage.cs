namespace SecReview.Tray;

/// <summary>
/// The picture of the notification-area icon, drawn in code: a shield in the colour of the
/// state with a white mark on it. Drawing it here means there are no image files to ship, it is
/// sharp at every size Windows asks for, and the rules of what each state looks like can be
/// tested.
/// </summary>
public static class TrayIconImage
{
    /// <summary>Each pixel is the average of this many samples a side, which smooths the edges.</summary>
    private const int Samples = 4;

    /// <summary>The shield's outline, in a square from 0 to 1: a peaked top, straight sides, a pointed foot.</summary>
    private static readonly (double X, double Y)[] Shield =
    [
        (0.50, 0.03), (0.90, 0.17), (0.90, 0.50), (0.84, 0.69), (0.70, 0.85), (0.50, 0.98),
        (0.30, 0.85), (0.16, 0.69), (0.10, 0.50), (0.10, 0.17),
    ];

    /// <summary>
    /// The picture as pixels, row by row from the top: blue, green, red, alpha per pixel, the
    /// colours already multiplied by the alpha (what Windows expects of an icon with soft edges).
    /// </summary>
    /// <param name="size">Width and height in pixels (16 to 256).</param>
    /// <param name="state">What the icon says.</param>
    /// <param name="darkTaskbar">Whether the taskbar is dark, which the grey of "unknown" and "paused" follows.</param>
    public static byte[] Draw(int size, TrayState state, bool darkTaskbar)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(size, 16);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(size, 256);

        (byte r, byte g, byte b) = Colour(state, darkTaskbar);
        byte[] pixels = new byte[size * size * 4];
        for (int y = 0; y < size; y++)
        {
            for (int x = 0; x < size; x++)
            {
                int inShield = 0;
                int inMark = 0;
                for (int sy = 0; sy < Samples; sy++)
                {
                    for (int sx = 0; sx < Samples; sx++)
                    {
                        double px = (x + ((sx + 0.5) / Samples)) / size;
                        double py = (y + ((sy + 0.5) / Samples)) / size;
                        if (InShield(px, py))
                        {
                            inShield++;
                            if (InMark(state, px, py))
                            {
                                inMark++;
                            }
                        }
                    }
                }

                if (inShield == 0)
                {
                    continue;
                }

                const int Total = Samples * Samples;
                int coloured = inShield - inMark;
                int at = ((y * size) + x) * 4;
                pixels[at] = (byte)(((b * coloured) + (255 * inMark)) / Total);
                pixels[at + 1] = (byte)(((g * coloured) + (255 * inMark)) / Total);
                pixels[at + 2] = (byte)(((r * coloured) + (255 * inMark)) / Total);
                pixels[at + 3] = (byte)(255 * inShield / Total);
            }
        }

        return pixels;
    }

    /// <summary>The shield's colour: green, orange, or a grey that shows on the taskbar's colour.</summary>
    internal static (byte R, byte G, byte B) Colour(TrayState state, bool darkTaskbar) => state switch
    {
        TrayState.Fine => (0x10, 0x8A, 0x3E),
        TrayState.NeedsAttention => (0xE0, 0x6C, 0x00),
        _ => darkTaskbar ? ((byte)0xA6, (byte)0xA6, (byte)0xA6) : ((byte)0x6B, (byte)0x6B, (byte)0x6B),
    };

    private static bool InShield(double x, double y)
    {
        // Even-odd rule: count the outline's edges that a ray to the right crosses.
        bool inside = false;
        for (int i = 0, j = Shield.Length - 1; i < Shield.Length; j = i++)
        {
            (double xi, double yi) = Shield[i];
            (double xj, double yj) = Shield[j];
            if ((yi > y) != (yj > y) && x < ((xj - xi) * (y - yi) / (yj - yi)) + xi)
            {
                inside = !inside;
            }
        }

        return inside;
    }

    /// <summary>The white mark: a tick, an exclamation mark, a pause sign or a dash.</summary>
    private static bool InMark(TrayState state, double x, double y) => state switch
    {
        TrayState.Fine => NearSegment(x, y, 0.30, 0.52, 0.45, 0.67, 0.055) || NearSegment(x, y, 0.45, 0.67, 0.71, 0.36, 0.055),
        TrayState.NeedsAttention => NearSegment(x, y, 0.50, 0.26, 0.50, 0.56, 0.06) || NearSegment(x, y, 0.50, 0.72, 0.50, 0.73, 0.065),
        TrayState.Snoozed => NearSegment(x, y, 0.40, 0.34, 0.40, 0.66, 0.05) || NearSegment(x, y, 0.60, 0.34, 0.60, 0.66, 0.05),
        _ => NearSegment(x, y, 0.34, 0.50, 0.66, 0.50, 0.055),
    };

    /// <summary>Whether a point lies within <paramref name="reach"/> of the line from A to B (a thick line with round ends).</summary>
    private static bool NearSegment(double x, double y, double ax, double ay, double bx, double by, double reach)
    {
        double dx = bx - ax;
        double dy = by - ay;
        double along = Math.Clamp((((x - ax) * dx) + ((y - ay) * dy)) / ((dx * dx) + (dy * dy)), 0, 1);
        double nx = ax + (along * dx) - x;
        double ny = ay + (along * dy) - y;
        return (nx * nx) + (ny * ny) <= reach * reach;
    }
}
