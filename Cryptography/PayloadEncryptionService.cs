using System.Security.Cryptography;
using System.Text;
using QrAuthenticity.Serialization;

namespace QrAuthenticity.Cryptography;

/// <summary>
/// Сервис оркестрации шифрования и расшифрования полезной нагрузки QR-кода.
/// Упаковывает зашифрованные данные алгоритмом Feistel-128-CBC в безопасный
/// текстовый конверт: ENC1.&lt;Base64Url(IV + Ciphertext)&gt;.
/// </summary>
public sealed class PayloadEncryptionService
{
    public const string DefaultMasterKey = "QrAuthenticity-MasterKey-2026-Feistel";
    public const string Prefix = "ENC1.";
    public const string AlgorithmName = "FEISTEL128-CBC";

    /// <summary>
    /// Проверяет, является ли переданная строка зашифрованным контейнером ENC1.
    /// </summary>
    public bool IsEncrypted(string? payload) =>
        !string.IsNullOrWhiteSpace(payload) &&
        payload.TrimStart().StartsWith(Prefix, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Зашифровывает открытый JSON полезной нагрузки с использованием симметричного ключа
    /// и возвращает текстовый защищенный контейнер ENC1.&lt;base64url&gt;.
    /// </summary>
    public string Encrypt(string plainJson, string? key = null)
    {
        if (string.IsNullOrWhiteSpace(plainJson))
            throw new ArgumentException("Открытый текст полезной нагрузки (JSON) не может быть пустым.", nameof(plainJson));

        string effectiveKey = string.IsNullOrWhiteSpace(key) ? DefaultMasterKey : key.Trim();
        byte[] keyBytes = Encoding.UTF8.GetBytes(effectiveKey);
        var cipher = new FeistelCipher(keyBytes);

        byte[] iv = RandomNumberGenerator.GetBytes(FeistelCipher.BlockSize);
        byte[] plainBytes = Encoding.UTF8.GetBytes(plainJson);
        byte[] cipherBytes = cipher.EncryptCbc(plainBytes, iv);

        byte[] combined = new byte[iv.Length + cipherBytes.Length];
        Buffer.BlockCopy(iv, 0, combined, 0, iv.Length);
        Buffer.BlockCopy(cipherBytes, 0, combined, iv.Length, cipherBytes.Length);

        return Prefix + Base64Url.Encode(combined);
    }

    /// <summary>
    /// Расшифровывает защищенный контейнер полезной нагрузки ENC1.&lt;base64url&gt;
    /// и возвращает исходный открытый JSON.
    /// Если передан открытый JSON (начинающийся с '{'), возвращает его без изменений для обратной совместимости.
    /// </summary>
    public string Decrypt(string payload, string? key = null)
    {
        if (string.IsNullOrWhiteSpace(payload))
            throw new ArgumentException("Полезная нагрузка не может быть пустой.", nameof(payload));

        var trimmed = payload.Trim();

        // Обратная совместимость с незашифрованным JSON
        if (trimmed.StartsWith('{'))
        {
            return trimmed;
        }

        if (!IsEncrypted(trimmed))
        {
            throw new FormatException("Полезная нагрузка не распознана: строка не является ни зашифрованным контейнером ENC1, ни JSON-структурой.");
        }

        string base64Part = trimmed[Prefix.Length..];
        byte[] combined = Base64Url.Decode(base64Part);

        if (combined.Length < FeistelCipher.BlockSize * 2)
        {
            throw new FormatException($"Длина зашифрованных данных ({combined.Length} байт) недостаточна (минимум {FeistelCipher.BlockSize * 2} байт для IV и блока данных).");
        }

        ReadOnlySpan<byte> iv = combined.AsSpan(0, FeistelCipher.BlockSize);
        ReadOnlySpan<byte> ciphertext = combined.AsSpan(FeistelCipher.BlockSize);

        string effectiveKey = string.IsNullOrWhiteSpace(key) ? DefaultMasterKey : key.Trim();
        byte[] keyBytes = Encoding.UTF8.GetBytes(effectiveKey);
        var cipher = new FeistelCipher(keyBytes);

        byte[] plainBytes = cipher.DecryptCbc(ciphertext, iv);
        return Encoding.UTF8.GetString(plainBytes);
    }
}
