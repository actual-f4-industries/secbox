using System;
using System.IO;
using System.Text.Json;
using System.Windows;

namespace Secbox.Sentinel.AlertUI;

// Entry: reads alert JSON from arg[0] (path to JSON file dropped by the
// editor / service), shows a single AlertWindow, exits when the user
// dismisses it.
//
// We deliberately don't pass the JSON on the command line directly —
// PowerShell history, ProcessExplorer, and any onlooker can read argv.
// File path arg + read-then-delete keeps the payload off the
// commandline-visible surface.
public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        AlertPayload payload;
        try
        {
            if (e.Args.Length < 1)
                throw new ArgumentException("usage: SecboxAlertUI <path-to-finding-json>");

            var path = e.Args[0];
            if (!File.Exists(path))
                throw new FileNotFoundException($"alert payload missing: {path}");

            var json = File.ReadAllText(path);
            payload = JsonSerializer.Deserialize<AlertPayload>(json, JsonOpts)
                ?? throw new InvalidDataException("alert payload deserialized as null");

            // Best-effort cleanup so the drop folder doesn't accumulate.
            try { File.Delete(path); } catch { }
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                $"secbox alert UI failed to start.\n\n{ex.GetType().Name}: {ex.Message}",
                "secbox",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            Shutdown(1);
            return;
        }

        var w = new AlertWindow(payload);
        w.Show();
    }

    static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
    };
}

// Wire shape — mirrors fields the editor drops in the JSON file.
// Extra fields are ignored (forward-compat); missing fields land as null.
public sealed class AlertPayload
{
    public string? Severity { get; set; }
    public string? Kind { get; set; }
    public string? Target { get; set; }
    public string? CallerAssembly { get; set; }
    public string? CallerMethod { get; set; }
    public string? Timestamp { get; set; }
    public int Pid { get; set; }
    public string? Action { get; set; }    // "Suspended" (decision panel) | "Blocked" | "Detected"
    public string? Note { get; set; }
}
