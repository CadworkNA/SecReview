using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation.Peers;

namespace SecReview.App;

/// <summary>
/// Looks at what is on screen the way a screen reader and a keyboard do: everything a person
/// can press or type into must say what it is, and must be reachable with the keyboard. It
/// walks the same tree of automation peers that Windows hands to assistive tools, not the
/// visual tree, so parts a control hides from them (the button inside an expander's header)
/// are not mistaken for nameless controls. Run on every automated start of the window, so a
/// control added without a name fails the build.
/// </summary>
internal static class AccessibilityAudit
{
    /// <summary>What is wrong, one line per control; empty when nothing is.</summary>
    /// <param name="root">The part of the window to look at.</param>
    /// <param name="atLeast">
    /// How many controls a person can operate must be found. Guards the audit itself: a walk
    /// that sees nothing would otherwise pass everything.
    /// </param>
    public static IReadOnlyList<string> Problems(UIElement root, int atLeast)
    {
        var problems = new List<string>();
        int operated = 0;
        FromVisualTree(root, problems, ref operated);
        if (operated < atLeast)
        {
            problems.Add($"Only {operated} controls were found for a screen reader; at least {atLeast} are on screen.");
        }

        return problems;
    }

    /// <summary>
    /// A layout panel has no presence of its own for assistive tools; what is inside it does.
    /// Goes down the visual tree to the first elements that have one and continues from there
    /// in their own tree.
    /// </summary>
    private static void FromVisualTree(DependencyObject element, List<string> problems, ref int operated)
    {
        if (element is UIElement { Visibility: Visibility.Collapsed })
        {
            return;
        }

        if (element is UIElement visible && FrameworkElementAutomationPeer.CreatePeerForElement(visible) is { } peer)
        {
            Walk(peer, problems, ref operated, depth: 0);
            return;
        }

        int children = Microsoft.UI.Xaml.Media.VisualTreeHelper.GetChildrenCount(element);
        for (int i = 0; i < children; i++)
        {
            FromVisualTree(Microsoft.UI.Xaml.Media.VisualTreeHelper.GetChild(element, i), problems, ref operated);
        }
    }

    private static void Walk(AutomationPeer peer, List<string> problems, ref int operated, int depth)
    {
        AutomationControlType type = peer.GetAutomationControlType();
        if (IsOperated(type) && peer.IsControlElement())
        {
            operated++;
            string name = peer.GetName();
            string what = $"{type} '{(string.IsNullOrWhiteSpace(name) ? peer.GetAutomationId() : name)}'";
            if (string.IsNullOrWhiteSpace(name))
            {
                problems.Add($"{what} ({peer.GetClassName()}) has no name for a screen reader.");
            }

            if (peer.IsEnabled() && !peer.IsKeyboardFocusable())
            {
                problems.Add($"{what} cannot be reached with the keyboard.");
            }
        }

        if (depth > 64 || peer.GetChildren() is not { } children)
        {
            return;
        }

        foreach (AutomationPeer child in children)
        {
            Walk(child, problems, ref operated, depth + 1);
        }
    }

    /// <summary>Whether a person presses, switches or types into a control of this kind.</summary>
    private static bool IsOperated(AutomationControlType type) => type is
        AutomationControlType.Button or AutomationControlType.SplitButton or AutomationControlType.Hyperlink or
        AutomationControlType.CheckBox or AutomationControlType.RadioButton or AutomationControlType.ComboBox or
        AutomationControlType.Edit or AutomationControlType.TabItem or AutomationControlType.MenuItem or
        AutomationControlType.ListItem or AutomationControlType.Slider;
}
