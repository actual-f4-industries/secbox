using System.Text.Json;
using System.Text.Json.Serialization;

namespace Secbox.Sentinel.Contracts;

// Shared JsonSerializerOptions for the wire format. Both client and service
// reference this so a schema or naming convention change happens in one
// place. camelCase + string enums match the existing Secbox bridge style.
public static class EnvelopeJson
{
    public static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = false,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };
}
