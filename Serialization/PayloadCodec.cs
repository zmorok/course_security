using System.Globalization;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using QrAuthenticity.Models;

namespace QrAuthenticity.Serialization;

public sealed class RussianDateOnlyJsonConverter : JsonConverter<DateOnly>
{
    private static readonly string[] Formats = ["dd.MM.yyyy", "yyyy-MM-dd"];

    public override DateOnly Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var str = reader.GetString();
        if (string.IsNullOrWhiteSpace(str))
            throw new JsonException("Date value cannot be empty.");

        foreach (var format in Formats)
        {
            if (DateOnly.TryParseExact(str, format, CultureInfo.InvariantCulture, DateTimeStyles.None, out var date))
            {
                return date;
            }
        }

        if (DateOnly.TryParse(str, CultureInfo.GetCultureInfo("ru-RU"), DateTimeStyles.None, out var ruDate))
        {
            return ruDate;
        }

        if (DateOnly.TryParse(str, CultureInfo.InvariantCulture, DateTimeStyles.None, out var invDate))
        {
            return invDate;
        }

        throw new JsonException($"Unable to parse DateOnly from '{str}'.");
    }

    public override void Write(Utf8JsonWriter writer, DateOnly value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(value.ToString("dd.MM.yyyy", CultureInfo.InvariantCulture));
    }
}

public sealed class NullableRussianDateOnlyJsonConverter : JsonConverter<DateOnly?>
{
    private static readonly string[] Formats = ["dd.MM.yyyy", "yyyy-MM-dd"];

    public override DateOnly? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.Null)
        {
            return null;
        }

        var str = reader.GetString();
        if (string.IsNullOrWhiteSpace(str))
        {
            return null;
        }

        foreach (var format in Formats)
        {
            if (DateOnly.TryParseExact(str, format, CultureInfo.InvariantCulture, DateTimeStyles.None, out var date))
            {
                return date;
            }
        }

        if (DateOnly.TryParse(str, CultureInfo.GetCultureInfo("ru-RU"), DateTimeStyles.None, out var ruDate))
        {
            return ruDate;
        }

        if (DateOnly.TryParse(str, CultureInfo.InvariantCulture, DateTimeStyles.None, out var invDate))
        {
            return invDate;
        }

        throw new JsonException($"Unable to parse DateOnly from '{str}'.");
    }

    public override void Write(Utf8JsonWriter writer, DateOnly? value, JsonSerializerOptions options)
    {
        if (value.HasValue)
        {
            writer.WriteStringValue(value.Value.ToString("dd.MM.yyyy", CultureInfo.InvariantCulture));
        }
        else
        {
            writer.WriteNullValue();
        }
    }
}

public sealed class PayloadCodec
{
    private static readonly JsonSerializerOptions Options = CreateOptions();

    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = false,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };
        options.Converters.Add(new RussianDateOnlyJsonConverter());
        options.Converters.Add(new NullableRussianDateOnlyJsonConverter());
        return options;
    }

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
