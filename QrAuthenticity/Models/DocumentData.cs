using System.Text.Json.Serialization;

namespace QrAuthenticity.Models;

public sealed record DocumentData(
    [property: JsonPropertyName("document")] string DocumentNumber,
    [property: JsonPropertyName("owner")] string Owner,
    [property: JsonPropertyName("issued")] DateOnly Issued,
    [property: JsonPropertyName("expires")] DateOnly? Expires)
{
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(DocumentNumber)) throw new ArgumentException("Document number is required.");
        if (string.IsNullOrWhiteSpace(Owner)) throw new ArgumentException("Owner is required.");
        if (Expires is not null && Expires.Value < Issued) throw new ArgumentException("Expiration date cannot be earlier than issue date.");
    }
}
