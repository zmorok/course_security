using System.Text.Json.Serialization;

namespace QrAuthenticity.Models;

public sealed record SignedPayload(
    [property: JsonPropertyName("v")] int Version,
    [property: JsonPropertyName("alg")] string Algorithm,
    [property: JsonPropertyName("kid")] string KeyId,
    [property: JsonPropertyName("data")] DocumentData Data,
    [property: JsonPropertyName("signature")] string Signature);

public sealed record UnsignedPayload(
    int Version,
    string Algorithm,
    string KeyId,
    DocumentData Data);
