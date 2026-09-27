using QrAuthenticity.Cryptography;
using QrAuthenticity.Models;
using QrAuthenticity.Serialization;

namespace QrAuthenticity.Verification;

/// <summary>
/// Сервис верификации подлинности и целостности данных QR-кода.
/// При необходимости производит расшифрование контейнера алгоритмом Feistel-128-CBC,
/// затем проверяет формат, доверие к открытому ключу издателя по Key ID,
/// математическую корректность подписи RSA-PSS над каноническими байтами и срок действия.
/// </summary>
public sealed class AuthenticityVerifier
{
    private readonly PayloadCodec _codec;
    private readonly PayloadCanonicalizer _canonicalizer;
    private readonly SignatureService _signatureService;
    private readonly TrustedKeyStore _trustedKeys;
    private readonly PayloadEncryptionService _encryptionService;

    public AuthenticityVerifier(
        PayloadCodec codec,
        PayloadCanonicalizer canonicalizer,
        SignatureService signatureService,
        TrustedKeyStore trustedKeys,
        PayloadEncryptionService? encryptionService = null)
    {
        _codec = codec;
        _canonicalizer = canonicalizer;
        _signatureService = signatureService;
        _trustedKeys = trustedKeys;
        _encryptionService = encryptionService ?? new PayloadEncryptionService();
    }

    /// <summary>
    /// Выполняет полную проверку переданной полезной нагрузки:
    /// как зашифрованного контейнера (ENC1...), так и открытого JSON.
    /// </summary>
    public VerificationResult Verify(string rawPayload, string? decryptionKey = null, DateOnly? today = null)
    {
        if (string.IsNullOrWhiteSpace(rawPayload))
        {
            return new VerificationResult(
                VerificationStatus.InvalidPayload,
                "Полезная нагрузка пуста.",
                RawPayload: rawPayload
            );
        }

        bool isEncrypted = _encryptionService.IsEncrypted(rawPayload);
        string jsonToVerify;

        if (isEncrypted)
        {
            try
            {
                jsonToVerify = _encryptionService.Decrypt(rawPayload, decryptionKey);
            }
            catch (Exception ex)
            {
                return new VerificationResult(
                    VerificationStatus.DecryptionFailed,
                    $"Ошибка расшифрования контейнера: {ex.Message}. Проверьте правильность симметричного ключа или целостность данных.",
                    IsEncrypted: true,
                    RawPayload: rawPayload
                );
            }
        }
        else
        {
            jsonToVerify = rawPayload;
        }

        SignedPayload payload;
        try
        {
            payload = _codec.Decode(jsonToVerify);
        }
        catch (Exception ex)
        {
            return new VerificationResult(
                VerificationStatus.InvalidPayload,
                $"Ошибка структуры контейнера данных: {ex.Message}",
                IsEncrypted: isEncrypted,
                DecryptedJson: jsonToVerify,
                RawPayload: rawPayload
            );
        }

        if (payload.Version != 1)
        {
            return new VerificationResult(
                VerificationStatus.UnsupportedVersion,
                $"Неподдерживаемая версия протокола: {payload.Version}. Ожидается версия 1.",
                payload,
                IsEncrypted: isEncrypted,
                DecryptedJson: jsonToVerify,
                RawPayload: rawPayload
            );
        }

        if (!string.Equals(payload.Algorithm, SignatureService.AlgorithmName, StringComparison.Ordinal))
        {
            return new VerificationResult(
                VerificationStatus.UnsupportedAlgorithm,
                $"Неподдерживаемый криптографический алгоритм: {payload.Algorithm}.",
                payload,
                IsEncrypted: isEncrypted,
                DecryptedJson: jsonToVerify,
                RawPayload: rawPayload
            );
        }

        if (!_trustedKeys.TryGet(payload.KeyId, out var publicKey) || publicKey is null)
        {
            return new VerificationResult(
                VerificationStatus.UnknownKey,
                $"Ключ издателя (Key ID: {payload.KeyId}) отсутствует в списке доверенных ключей.",
                payload,
                IsEncrypted: isEncrypted,
                DecryptedJson: jsonToVerify,
                RawPayload: rawPayload
            );
        }

        try
        {
            var unsigned = new UnsignedPayload(payload.Version, payload.Algorithm, payload.KeyId, payload.Data);
            var canonicalBytes = _canonicalizer.Canonicalize(unsigned);
            var signatureBytes = Base64Url.Decode(payload.Signature);

            if (!_signatureService.Verify(canonicalBytes, signatureBytes, publicKey))
            {
                return new VerificationResult(
                    VerificationStatus.InvalidSignature,
                    "Цифровая подпись недействительна! Целостность нарушена: данные документа были изменены или подпись сфальсифицирована.",
                    payload,
                    IsEncrypted: isEncrypted,
                    DecryptedJson: jsonToVerify,
                    RawPayload: rawPayload
                );
            }

            var currentDate = today ?? DateOnly.FromDateTime(DateTime.Today);
            if (payload.Data.Expires is not null && payload.Data.Expires.Value < currentDate)
            {
                return new VerificationResult(
                    VerificationStatus.Expired,
                    "Цифровая подпись математически верна, однако срок действия документа истек.",
                    payload,
                    IsEncrypted: isEncrypted,
                    DecryptedJson: jsonToVerify,
                    RawPayload: rawPayload
                );
            }

            return new VerificationResult(
                VerificationStatus.Valid,
                "Подлинность и целостность подтверждены: цифровая подпись корректна, ключ издателя является доверенным.",
                payload,
                IsEncrypted: isEncrypted,
                DecryptedJson: jsonToVerify,
                RawPayload: rawPayload
            );
        }
        catch (Exception ex)
        {
            return new VerificationResult(
                VerificationStatus.InvalidPayload,
                $"Ошибка при обработке канонических данных или подписи: {ex.Message}",
                payload,
                IsEncrypted: isEncrypted,
                DecryptedJson: jsonToVerify,
                RawPayload: rawPayload
            );
        }
    }
}
