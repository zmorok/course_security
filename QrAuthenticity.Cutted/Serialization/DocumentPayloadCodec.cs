using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using QrAuthenticity.Cutted.Models;
using QrAuthenticity.Models;
using QrAuthenticity.Serialization;

namespace QrAuthenticity.Cutted.Serialization;

public sealed class DocumentPayloadCodec
{
    public const int CurrentVersion = 2;

    private static readonly JsonSerializerOptions Options = CreateOptions();

    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            RespectNullableAnnotations = true,
            RespectRequiredConstructorParameters = true
        };
        options.Converters.Add(new RussianDateOnlyJsonConverter());
        options.Converters.Add(new NullableRussianDateOnlyJsonConverter());
        return options;
    }

    public string Encode(DocumentData data)
    {
        ArgumentNullException.ThrowIfNull(data);
        data.Validate();
        return JsonSerializer.Serialize(new DocumentPayload(CurrentVersion, data), Options);
    }

    public DocumentPayload Decode(string json)
    {
        try
        {
            var payload = JsonSerializer.Deserialize<DocumentPayload>(json, Options)
                ?? throw new FormatException("Контейнер данных пуст.");
            if (payload.Data is null)
                throw new FormatException("Реквизиты документа отсутствуют.");
            payload.Data.Validate();
            return payload;
        }
        catch (JsonException ex)
        {
            throw new FormatException("Некорректная структура JSON-контейнера.", ex);
        }
    }
}
