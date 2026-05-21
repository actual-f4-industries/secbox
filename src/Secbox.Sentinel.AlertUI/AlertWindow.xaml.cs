using System;
using System.Globalization;
using System.Windows;
using System.Windows.Input;

namespace Secbox.Sentinel.AlertUI;

public partial class AlertWindow : Window
{
    readonly AlertPayload _payload;

    public AlertWindow(AlertPayload payload)
    {
        InitializeComponent();
        _payload = payload;
        Populate(payload);
        SelectFooter(payload);
    }

    void Populate(AlertPayload p)
    {
        ActionText.Text  = string.IsNullOrEmpty(p.Action)
            ? (p.Severity ?? "Critical")
            : p.Action;
        KindText.Text    = p.Kind ?? "(unknown)";
        TargetText.Text  = string.IsNullOrEmpty(p.Target) ? "(no target)" : p.Target;
        LibraryText.Text = string.IsNullOrEmpty(p.CallerAssembly)
            ? "(no managed attribution)"
            : $"{p.CallerAssembly}::{p.CallerMethod ?? "(unknown method)"}";
        TimeText.Text    = FormatTime(p.Timestamp);
        PidText.Text     = p.Pid > 0 ? p.Pid.ToString(CultureInfo.InvariantCulture) : "(unknown)";

        NoteBox.Text = string.IsNullOrEmpty(p.Note)
            ? DefaultNote(p)
            : p.Note;

        SubtitleText.Text = string.IsNullOrEmpty(p.CallerAssembly)
            ? "A monitored event was classified as Critical."
            : $"Detected from library: {p.CallerAssembly}";
    }

    static string DefaultNote(AlertPayload p) =>
        IsSuspended(p)
            ? "The editor's calling thread is blocked inside Tier E's Harmony prefix until "
                + "you choose. Allow lets this call run once; Allow & Trust persists the library "
                + "in %LOCALAPPDATA%\\secbox\\managed-call-trust.json and future calls skip this "
                + "prompt; Kill terminates the editor (you lose unsaved work)."
            : "Runtime monitoring intercepted a library-attributed call classified as Critical. "
                + "The call has been recorded in the audit log.";

    // Suspended mode shows the decision panel (Allow/Trust/Kill/Remove).
    // Already-resolved findings (Detected, Blocked) show the Dismiss footer.
    static bool IsSuspended(AlertPayload p) =>
        string.Equals(p.Action, "Suspended", StringComparison.OrdinalIgnoreCase);

    void SelectFooter(AlertPayload p)
    {
        if (IsSuspended(p))
        {
            DecisionPanel.Visibility = Visibility.Visible;
            DismissPanel.Visibility = Visibility.Collapsed;
        }
        else
        {
            DecisionPanel.Visibility = Visibility.Collapsed;
            DismissPanel.Visibility = Visibility.Visible;
        }
    }

    // ──────────── Decision-panel handlers (Suspended mode) ────────────
    void Allow_Click(object sender, RoutedEventArgs e)        => Application.Current.Shutdown(AlertDecision.Allow);
    void AllowTrust_Click(object sender, RoutedEventArgs e)   => Application.Current.Shutdown(AlertDecision.AllowAndTrust);
    void Kill_Click(object sender, RoutedEventArgs e)         => Application.Current.Shutdown(AlertDecision.Kill);

    // Destructive + irreversible: confirm before terminating the editor and
    // deleting the library from disk. Cancel leaves the thread still suspended
    // so the user can pick a softer option.
    void KillRemove_Click(object sender, RoutedEventArgs e)
    {
        var lib = string.IsNullOrEmpty(_payload.CallerAssembly) ? "this library" : _payload.CallerAssembly;
        var confirm = MessageBox.Show(
            this,
            "This will terminate the editor and permanently delete the library:\n\n"
            + $"    {lib}\n\n"
            + "from this project's Libraries folder. Any unsaved work is lost. Files the "
            + "editor still has open are deleted the next time it starts.\n\nContinue?",
            "secbox — kill & remove library",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No);

        if (confirm == MessageBoxResult.Yes)
            Application.Current.Shutdown(AlertDecision.KillAndRemove);
    }

    // ──────────── Dismiss-panel handler (informational mode) ───────────
    void Dismiss_Click(object sender, RoutedEventArgs e)      => Application.Current.Shutdown(AlertDecision.Block);

    // ──────────── Custom chrome (WindowStyle=None) ────────────
    // Drag the title bar to move the borderless window.
    void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ButtonState != MouseButtonState.Pressed) return;
        try { DragMove(); } catch { /* DragMove throws if the button released mid-call — ignore */ }
    }

    // ✕ in the title bar. Closing == Block (exit 0): the documented fail-safe
    // when the user dismisses without making an explicit decision.
    void Close_Click(object sender, RoutedEventArgs e) => Close();

    static string FormatTime(string? iso)
    {
        if (string.IsNullOrEmpty(iso)) return "(unknown)";
        if (DateTimeOffset.TryParse(iso, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dt))
            return dt.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
        return iso;
    }
}
