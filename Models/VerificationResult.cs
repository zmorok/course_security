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
    Expired
}

public sealed record VerificationResult(
    VerificationStatus Status,
    string Message,
    SignedPayload? Payload = null)
{
    public bool IsCryptographicallyValid => Status is VerificationStatus.Valid or VerificationStatus.Expired;
}
