using System.Text.Json;

namespace Secbox.Core.RuntimeSensors;

// Persisted "trusted libraries" list — assemblies the user explicitly
// allowed for Tier E managed-call tripwires. When a library is in the
// trust set, ManagedCallSensor allows its Process.Start calls through
// without prompting the user via AlertUI. The "Allow & Trust" exit code
// from the WPF dialog persists the calling library here.
//
// Storage: %LOCALAPPDATA%\secbox\managed-call-trust.json. Plain JSON, no
// signature — the trust list lives in the user's profile and is only
// meaningful inside that user's editor session. Tampering risk is
// equivalent to "user edits their own config".
//
// Thread-safety: a lock guards the in-memory set on writes. Reads are
// lock-free (HashSet.Contains is safe for read with a single writer that
// republishes the whole set on Save).
public sealed class ManagedCallTrustStore
{
    public static string FilePath =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "secbox", "managed-call-trust.json");

    readonly Lock _gate = new();
    HashSet<string> _trusted = new(StringComparer.OrdinalIgnoreCase);

    public static ManagedCallTrustStore Load()
    {
        var store = new ManagedCallTrustStore();
        try
        {
            if (!File.Exists(FilePath)) return store;
            var json = File.ReadAllText(FilePath);
            var dto = JsonSerializer.Deserialize<TrustFile>(json, JsonOpts);
            if (dto?.Trusted == null) return store;
            store._trusted = new HashSet<string>(dto.Trusted, StringComparer.OrdinalIgnoreCase);
        }
        catch { /* corrupt file → start fresh; safer than crashing the sensor */ }
        return store;
    }

    public bool IsTrusted(string? assemblyName)
    {
        if (string.IsNullOrEmpty(assemblyName)) return false;
        return _trusted.Contains(assemblyName);
    }

    // Add the assembly to the trust set and write the new state to disk.
    // Best-effort persistence — if the write fails (locked file, ACL
    // mismatch), the trust still applies for the current session.
    public void Trust(string assemblyName)
    {
        if (string.IsNullOrEmpty(assemblyName)) return;
        lock (_gate)
        {
            if (!_trusted.Add(assemblyName)) return; // already there
            TrySave();
        }
    }

    void TrySave()
    {
        try
        {
            var dir = Path.GetDirectoryName(FilePath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            var dto = new TrustFile
            {
                Version = 1,
                Trusted = _trusted.OrderBy(s => s, StringComparer.Ordinal).ToList(),
                UpdatedAt = DateTimeOffset.UtcNow.ToString("O"),
            };
            var tmp = FilePath + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(dto, JsonOpts));
            File.Move(tmp, FilePath, overwrite: true);
        }
        catch { /* swallow — in-memory trust still active for the session */ }
    }

    static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    sealed class TrustFile
    {
        public int Version { get; set; } = 1;
        public List<string> Trusted { get; set; } = new();
        public string? UpdatedAt { get; set; }
    }
}
