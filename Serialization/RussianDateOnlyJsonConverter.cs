using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

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
