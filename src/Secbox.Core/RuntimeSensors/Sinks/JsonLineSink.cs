using System.Text.Json;
using System.Text.Json.Serialization;

namespace Secbox.Core.RuntimeSensors.Sinks;

// Forwards every AttributedFinding to an external Action<string>. Used by
// the bridge: SecboxApi.AttachRuntimeSensors stores the adapter's
// Action<string> here so events flow back across the ALC boundary.
public sealed class JsonLineSink : IOutputSink
{
    public string Id => "json-line";
    readonly Action<string> _sink;

    static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = false,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public JsonLineSink(Action<string> sink) { _sink = sink; }

    public void Emit(AttributedFinding f)
    {
        try
        {
            var json = JsonSerializer.Serialize(f, JsonOpts);
            _sink(json);
        }
        catch { /* sink contract: never throw back into the correlator */ }
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}
