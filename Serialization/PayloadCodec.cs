using System.Text.Encodings.Web;
using System.Text.Json;
using QrAuthenticity.Models;

namespace QrAuthenticity.Serialization;

public sealed class PayloadCodec
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    public string Encode(SignedPayload payload) => JsonSerializer.Serialize(payload, Options);

    public SignedPayload Decode(string json)
    {
        try
        {
            var payload = JsonSerializer.Deserialize<SignedPayload>(json, Options)
                          ?? throw new FormatException("Payload is empty.");
            if (string.IsNullOrWhiteSpace(payload.Algorithm) || string.IsNullOrWhiteSpace(payload.KeyId) || string.IsNullOrWhiteSpace(payload.Signature))
                throw new FormatException("Required payload fields are missing.");
            payload.Data.Validate();
            return payload;
        }
        catch (JsonException ex) { throw new FormatException("Invalid payload JSON.", ex); }
    }
}
