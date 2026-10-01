using System.Security.Cryptography;
using QrAuthenticity.Cryptography;
using QrAuthenticity.Cutted.Models;
using QrAuthenticity.Cutted.Serialization;
using QrAuthenticity.Models;

namespace QrAuthenticity.Cutted.Services;

/// <summary>Создание и чтение зашифрованных реквизитов документа.</summary>
public sealed class EncryptedDocumentService
{
    private readonly DocumentPayloadCodec _codec = new();
    private readonly PayloadEncryptionService _encryption = new();

    public string Create(DocumentData data, string? key = null) =>
        _encryption.Encrypt(_codec.Encode(data), key);

    public QrReadingResult Read(string? rawPayload, string? key = null)
    {
        if (string.IsNullOrWhiteSpace(rawPayload) || !_encryption.IsEncrypted(rawPayload))
        {
            return new(QrReadingStatus.InvalidPayload,
                "Ожидается зашифрованная строка из QR-кода. Загрузите изображение или вставьте считанный шифртекст.");
        }

        string json;
        try
        {
            json = _encryption.Decrypt(rawPayload, key);
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException or CryptographicException)
        {
            return new(QrReadingStatus.DecryptionFailed,
                "Не удалось расшифровать данные. Проверьте симметричный ключ и правильность считанной строки.");
        }

        DocumentPayload payload;
        try
        {
            payload = _codec.Decode(json);
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException)
        {
            return new(QrReadingStatus.InvalidPayload,
                "После расшифрования не получен корректный контейнер реквизитов. Проверьте ключ и формат QR-кода.");
        }

        if (payload.Version != DocumentPayloadCodec.CurrentVersion)
        {
            return new(QrReadingStatus.UnsupportedVersion,
                $"Неподдерживаемая версия данных: {payload.Version}. Ожидается версия {DocumentPayloadCodec.CurrentVersion}.");
        }

        return new(QrReadingStatus.Success, "QR-код прочитан, данные успешно расшифрованы.", payload.Data, json);
    }
}
