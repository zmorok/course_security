using System.Security.Cryptography;

namespace QrAuthenticity.Cryptography;

public sealed class SignatureService
{
    public const string AlgorithmName = "RSA-PSS-SHA256";

    public byte[] Sign(ReadOnlySpan<byte> canonicalBytes, RSA privateKey) =>
        privateKey.SignData(canonicalBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

    public bool Verify(ReadOnlySpan<byte> canonicalBytes, ReadOnlySpan<byte> signature, RSA publicKey) =>
        publicKey.VerifyData(canonicalBytes, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
}
