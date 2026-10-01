using System.Text.Json.Serialization;
using QrAuthenticity.Models;

namespace QrAuthenticity.Cutted.Models;

public sealed record DocumentPayload(
    [property: JsonPropertyName("v"), JsonRequired] int Version,
    [property: JsonPropertyName("data"), JsonRequired] DocumentData Data);

public enum QrReadingStatus
{
    Success,
    InvalidPayload,
    DecryptionFailed,
    UnsupportedVersion
}

public sealed record QrReadingResult(
    QrReadingStatus Status,
    string Message,
    DocumentData? Data = null,
    string? DecryptedJson = null);
