namespace QrAuthenticity.Models;

public enum VerificationStatus
{
    Valid,
    InvalidSignature,
    UnknownKey,
    InvalidPayload,
    QrNotDecoded,
    UnsupportedVersion,
    UnsupportedAlgorithm,
    Expired,
    DecryptionFailed
}

public sealed record VerificationResult(
    VerificationStatus Status,
    string Message,
    SignedPayload? Payload = null,
    bool IsEncrypted = false,
    string? DecryptedJson = null,
    string? RawPayload = null)
{
    public bool IsCryptographicallyValid => Status is VerificationStatus.Valid or VerificationStatus.Expired;
}
