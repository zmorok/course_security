using System.Buffers;
using System.Text.Encodings.Web;
using System.Text.Json;
using QrAuthenticity.Models;

namespace QrAuthenticity.Serialization;

/// <summary>
/// Формирует единственно допустимое каноническое байтовое представление для вычисления и проверки цифровой подписи.
/// Порядок свойств, нормализация пробелов и формат дат строго зафиксированы в спецификации протокола.
/// </summary>
public sealed class PayloadCanonicalizer
{
    public byte[] Canonicalize(UnsignedPayload payload)
    {
        payload.Data.Validate();
        var buffer = new ArrayBufferWriter<byte>();
        using var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions
        {
            Indented = false,
            SkipValidation = false,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        });
        writer.WriteStartObject();
        writer.WriteNumber("v", payload.Version);
        writer.WriteString("alg", payload.Algorithm);
        writer.WriteString("kid", payload.KeyId);
        writer.WritePropertyName("data");
        writer.WriteStartObject();
        writer.WriteString("document", payload.Data.DocumentNumber.Trim());
        writer.WriteString("owner", payload.Data.Owner.Trim());
        writer.WriteString("issued", payload.Data.Issued.ToString("yyyy-MM-dd"));
        if (payload.Data.Expires is not null)
            writer.WriteString("expires", payload.Data.Expires.Value.ToString("yyyy-MM-dd"));
        else
            writer.WriteNull("expires");
        writer.WriteEndObject();
        writer.WriteEndObject();
        writer.Flush();
        return buffer.WrittenSpan.ToArray();
    }
}
