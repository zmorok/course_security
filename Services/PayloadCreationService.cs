using System.Security.Cryptography;
using QrAuthenticity.Cryptography;
using QrAuthenticity.Models;
using QrAuthenticity.Serialization;

namespace QrAuthenticity.Services;

/// <summary>
/// Сервис оркестрации процесса формирования подписанного (и опционально зашифрованного) QR-контейнера:
/// Валидация реквизитов -> вычисление Key ID -> канонизация данных -> вычисление ЭЦП (RSA-PSS) ->
/// упаковка в JSON -> (опционально) симметричное шифрование Feistel-128-CBC.
/// </summary>
public sealed class PayloadCreationService
{
    private readonly KeyManager _keys;
    private readonly SignatureService _signatures;
    private readonly PayloadCanonicalizer _canonicalizer;
    private readonly PayloadCodec _codec;
    private readonly PayloadEncryptionService _encryption;

    public PayloadCreationService(
        KeyManager? keys = null,
        SignatureService? signatures = null,
        PayloadCanonicalizer? canonicalizer = null,
        PayloadCodec? codec = null,
        PayloadEncryptionService? encryption = null)
    {
        _keys = keys ?? new KeyManager();
        _signatures = signatures ?? new SignatureService();
        _canonicalizer = canonicalizer ?? new PayloadCanonicalizer();
        _codec = codec ?? new PayloadCodec();
        _encryption = encryption ?? new PayloadEncryptionService();
    }

    /// <summary>
    /// Создает строго типизированный объект SignedPayload с канонизацией и подписью закрытым ключом.
    /// </summary>
    public SignedPayload Create(DocumentData data, RSA privateKey)
    {
        data.Validate();
        var keyId = _keys.ComputeKeyId(privateKey);
        var unsigned = new UnsignedPayload(1, SignatureService.AlgorithmName, keyId, data);
        var canonicalBytes = _canonicalizer.Canonicalize(unsigned);
        var signatureBytes = _signatures.Sign(canonicalBytes, privateKey);

        return new SignedPayload(
            unsigned.Version,
            unsigned.Algorithm,
            unsigned.KeyId,
            data,
            Base64Url.Encode(signatureBytes)
        );
    }

    /// <summary>
    /// Создает подписанный контейнер и сериализует его в строку JSON.
    /// </summary>
    public string CreateJson(DocumentData data, RSA privateKey) => _codec.Encode(Create(data, privateKey));

    /// <summary>
    /// Создает подписанный контейнер и зашифровывает его алгоритмом Feistel-128-CBC в формат ENC1.&lt;base64url&gt;.
    /// </summary>
    public string CreateEncryptedPayload(DocumentData data, RSA privateKey, string? encryptionKey = null)
    {
        string json = CreateJson(data, privateKey);
        return _encryption.Encrypt(json, encryptionKey);
    }
}
