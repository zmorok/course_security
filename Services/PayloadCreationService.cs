using System.Security.Cryptography;
using QrAuthenticity.Cryptography;
using QrAuthenticity.Models;
using QrAuthenticity.Serialization;

namespace QrAuthenticity.Services;

/// <summary>
/// Сервис оркестрации процесса формирования подписанного QR-контейнера:
/// Валидация реквизитов -> вычисление Key ID -> канонизация данных -> вычисление ЭЦП (RSA-PSS) -> сериализация в JSON.
/// </summary>
public sealed class PayloadCreationService
{
    private readonly KeyManager _keys;
    private readonly SignatureService _signatures;
    private readonly PayloadCanonicalizer _canonicalizer;
    private readonly PayloadCodec _codec;

    public PayloadCreationService(
        KeyManager? keys = null,
        SignatureService? signatures = null,
        PayloadCanonicalizer? canonicalizer = null,
        PayloadCodec? codec = null)
    {
        _keys = keys ?? new KeyManager();
        _signatures = signatures ?? new SignatureService();
        _canonicalizer = canonicalizer ?? new PayloadCanonicalizer();
        _codec = codec ?? new PayloadCodec();
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
    /// Создает подписанный контейнер и сериализует его в строку JSON для записи в QR-код.
    /// </summary>
    public string CreateJson(DocumentData data, RSA privateKey) => _codec.Encode(Create(data, privateKey));
}
