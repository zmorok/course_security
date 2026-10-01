using System.IO;
using System.Security.Cryptography;

namespace QrAuthenticity.Cryptography;

/// <summary>
/// Сервис управления асимметричными ключами RSA:
/// генерация, экспорт и импорт в стандартных форматах PKCS#8 и SPKI (PEM),
/// а также вычисление уникального идентификатора ключа (Key ID).
/// </summary>
public sealed class KeyManager
{
    /// <summary>
    /// Создает новую криптографическую пару ключей RSA с длиной модуля не менее 2048 бит.
    /// </summary>
    public RSA GenerateRsa(int keySize = 2048)
    {
        if (keySize < 2048)
        {
            throw new ArgumentOutOfRangeException(nameof(keySize), "Для криптографической стойкости используйте ключ размером от 2048 бит.");
        }

        var rsa = RSA.Create();
        rsa.KeySize = keySize;
        return rsa;
    }

    /// <summary>
    /// Экспортирует закрытый ключ в стандартном текстовом формате PKCS#8 PEM.
    /// </summary>
    public string ExportPrivatePem(RSA rsa) => rsa.ExportPkcs8PrivateKeyPem();

    /// <summary>
    /// Экспортирует открытый ключ в стандартном формате SubjectPublicKeyInfo (SPKI) PEM.
    /// </summary>
    public string ExportPublicPem(RSA rsa) => rsa.ExportSubjectPublicKeyInfoPem();

    /// <summary>
    /// Импортирует закрытый ключ из строки PEM.
    /// </summary>
    public RSA ImportPrivatePem(string pem)
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        return rsa;
    }

    /// <summary>
    /// Импортирует открытый ключ из строки PEM.
    /// </summary>
    public RSA ImportPublicPem(string pem)
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        return rsa;
    }

    /// <summary>
    /// Сохраняет открытый ключ в файл .pem.
    /// </summary>
    public void SavePublicPem(RSA rsa, string filePath)
    {
        File.WriteAllText(filePath, ExportPublicPem(rsa));
    }

    /// <summary>
    /// Сохраняет закрытый ключ в файл .pem.
    /// </summary>
    public void SavePrivatePem(RSA rsa, string filePath)
    {
        File.WriteAllText(filePath, ExportPrivatePem(rsa));
    }

    /// <summary>
    /// Вычисляет открытый идентификатор ключа (Key ID) как первые 8 байт (16 hex-символов)
    /// от SHA-256 хеша структуры SubjectPublicKeyInfo (SPKI).
    /// Key ID не является секретом и служит для сопоставления подписи с доверенным ключом.
    /// </summary>
    public string ComputeKeyId(RSA rsa)
    {
        var spki = rsa.ExportSubjectPublicKeyInfo();
        var digest = SHA256.HashData(spki);
        return Convert.ToHexString(digest.AsSpan(0, 8));
    }
}
