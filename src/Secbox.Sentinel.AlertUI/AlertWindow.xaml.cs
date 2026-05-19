using System;
using System.Globalization;
using System.Windows;

namespace Secbox.Sentinel.AlertUI;

public partial class AlertWindow : Window
{
    public AlertWindow(AlertPayload payload)
    {
        InitializeComponent();
        Populate(payload);
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
            ? "Runtime monitoring intercepted a library-attributed call classified as Critical. "
              + "The call has been recorded in the audit log. If the policy was configured to block, "
              + "the underlying action did not execute and the calling library will observe a null/false "
              + "return value (and may throw on the next member access)."
            : p.Note;

        SubtitleText.Text = string.IsNullOrEmpty(p.CallerAssembly)
            ? "A monitored event was classified as Critical."
            : $"Detected from library: {p.CallerAssembly}";
    }

    static string FormatTime(string? iso)
    {
        if (string.IsNullOrEmpty(iso)) return "(unknown)";
        if (DateTimeOffset.TryParse(iso, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dt))
            return dt.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
        return iso;
    }

    void Dismiss_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }
}
