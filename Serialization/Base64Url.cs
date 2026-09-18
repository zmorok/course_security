namespace QrAuthenticity.Serialization;

public static class Base64Url
{
    public static string Encode(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    public static byte[] Decode(string value)
    {
        if (value is null)
            throw new ArgumentNullException(nameof(value));
        if (value.Length == 0)
            return Array.Empty<byte>();
        if (string.IsNullOrWhiteSpace(value))
            throw new FormatException("Base64URL value contains only whitespace.");

        var normalized = value
            .Replace('-', '+')
            .Replace('_', '/');

        normalized += (normalized.Length % 4) switch
        {
            0 => "",
            2 => "==",
            3 => "=",
            _ => throw new FormatException("Invalid Base64URL length.")
        };

        return Convert.FromBase64String(normalized);
    }
}