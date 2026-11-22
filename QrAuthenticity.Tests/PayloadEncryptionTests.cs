using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using QrAuthenticity.Cryptography;
using QrAuthenticity.Models;
using QrAuthenticity.Serialization;
using QrAuthenticity.Services;
using QrAuthenticity.Verification;

namespace QrAuthenticity.Tests;

[TestClass]
public sealed class PayloadEncryptionTests
{
    private static KeyManager _keyManager = null!;
    private static RSA _trustedRsa = null!;
    private static RSA _attackerRsa = null!;
    private static string _trustedPublicPem = null!;

    private TrustedKeyStore _trustedKeys = null!;
    private PayloadEncryptionService _encryptionService = null!;
    private PayloadCreationService _creator = null!;
    private AuthenticityVerifier _verifier = null!;

    [ClassInitialize]
    public static void ClassSetup(TestContext _)
    {
        _keyManager = new KeyManager();
        _trustedRsa = _keyManager.GenerateRsa(2048);
        _attackerRsa = _keyManager.GenerateRsa(2048);
        _trustedPublicPem = _keyManager.ExportPublicPem(_trustedRsa);
    }

    [ClassCleanup]
    public static void ClassCleanup()
    {
        _trustedRsa.Dispose();
        _attackerRsa.Dispose();
    }

    [TestInitialize]
    public void Setup()
    {
        _trustedKeys = new TrustedKeyStore();
        _trustedKeys.AddPublicKey(_trustedPublicPem, "Доверенный издатель");
        _encryptionService = new PayloadEncryptionService();
        _creator = new PayloadCreationService(_keyManager, new SignatureService(), new PayloadCanonicalizer(), new PayloadCodec(), _encryptionService);
        _verifier = new AuthenticityVerifier(
            new PayloadCodec(),
            new PayloadCanonicalizer(),
            new SignatureService(),
            _trustedKeys,
            _encryptionService
        );
    }

    [TestCleanup]
    public void Cleanup()
    {
        _trustedKeys.Dispose();
    }

    [TestMethod]
    public void PayloadEncryptionService_Encrypt_ProducesEnc1PrefixAndDetectsContainer()
    {
        string sampleJson = $"{{\"v\":1,\"alg\":\"{SignatureService.AlgorithmName}\",\"doc\":\"DOC-123\"}}";
        string encrypted = _encryptionService.Encrypt(sampleJson);

        Assert.IsTrue(encrypted.StartsWith(PayloadEncryptionService.Prefix, StringComparison.Ordinal));
        Assert.IsTrue(_encryptionService.IsEncrypted(encrypted));
        Assert.IsTrue(_encryptionService.IsEncrypted("  enc1.abc"));
        Assert.IsFalse(_encryptionService.IsEncrypted(sampleJson));
        Assert.IsFalse(_encryptionService.IsEncrypted(null));
        Assert.IsFalse(_encryptionService.IsEncrypted(""));
        Assert.IsFalse(encrypted.Contains("DOC-123", StringComparison.Ordinal));
    }

    [TestMethod]
    public void PayloadEncryptionService_RoundTripAndCompatibility_WorkAsExpected()
    {
        string sampleJson = $"{{\"v\":1,\"alg\":\"{SignatureService.AlgorithmName}\",\"doc\":\"DOC-123\",\"owner\":\"Иван Тестовый\"}}";

        string encryptedDefault = _encryptionService.Encrypt(sampleJson);
        Assert.AreEqual(sampleJson, _encryptionService.Decrypt(encryptedDefault));

        string encryptedCustom = _encryptionService.Encrypt(sampleJson, "  My-Custom-Passphrase-2026  ");
        string decryptedCustom = _encryptionService.Decrypt(encryptedCustom, "My-Custom-Passphrase-2026");
        Assert.AreEqual(sampleJson, decryptedCustom);

        Assert.AreEqual(sampleJson, _encryptionService.Decrypt($"  {sampleJson}  "));
    }

    [TestMethod]
    public void PayloadEncryptionService_InvalidInputs_ThrowExpectedExceptions()
    {
        Assert.ThrowsException<ArgumentException>(() => _encryptionService.Encrypt(""));
        Assert.ThrowsException<ArgumentException>(() => _encryptionService.Encrypt("   "));
        Assert.ThrowsException<ArgumentException>(() => _encryptionService.Decrypt(""));
        Assert.ThrowsException<FormatException>(() => _encryptionService.Decrypt("PLAIN-TEXT"));
        Assert.ThrowsException<FormatException>(() => _encryptionService.Decrypt("ENC1.!@#$"));
        Assert.ThrowsException<FormatException>(() => _encryptionService.Decrypt("ENC1." + Base64Url.Encode(new byte[16])));
    }

    [DataTestMethod]
    [DataRow(null)]
    [DataRow("Custom-Symmetric-Key-2026")]
    public void AuthenticityVerifier_VerifyEncryptedPayload_ValidKey_Succeeds(string? symmetricKey)
    {
        var doc = new DocumentData("DOC-2026-ENC-001", "Сергеев Сергей", new DateOnly(2026, 3, 1), new DateOnly(2028, 3, 1));
        var encryptedPayload = _creator.CreateEncryptedPayload(doc, _trustedRsa, encryptionKey: symmetricKey);

        var result = _verifier.Verify(encryptedPayload, decryptionKey: symmetricKey, today: new DateOnly(2026, 6, 1));

        Assert.AreEqual(VerificationStatus.Valid, result.Status);
        Assert.IsTrue(result.IsCryptographicallyValid);
        Assert.IsTrue(result.IsEncrypted);
        Assert.IsNotNull(result.Payload);
        Assert.AreEqual("DOC-2026-ENC-001", result.Payload.Data.DocumentNumber);
        Assert.IsNotNull(result.DecryptedJson);
        Assert.IsTrue(result.DecryptedJson.Contains("DOC-2026-ENC-001", StringComparison.Ordinal));
    }

    [TestMethod]
    public void AuthenticityVerifier_VerifyEncryptedPayload_WrongKey_ReturnsDecryptionFailed()
    {
        var doc = new DocumentData("DOC-2026-ENC-002", "Петров Петр", new DateOnly(2026, 3, 1), null);
        var encryptedPayload = _creator.CreateEncryptedPayload(doc, _trustedRsa, encryptionKey: "SecretKeyA");

        var result = _verifier.Verify(encryptedPayload, decryptionKey: "SecretKeyB");

        Assert.AreEqual(VerificationStatus.DecryptionFailed, result.Status);
        Assert.IsFalse(result.IsCryptographicallyValid);
        Assert.IsTrue(result.IsEncrypted);
        Assert.IsNull(result.Payload);
    }

    [TestMethod]
    public void AuthenticityVerifier_CorruptedEncryptedPayload_FailsVerification()
    {
        var doc = new DocumentData("DOC-CORRUPT", "Иванов Иван", new DateOnly(2026, 3, 1), null);
        var encrypted = _creator.CreateEncryptedPayload(doc, _trustedRsa);

        byte[] raw = Base64Url.Decode(encrypted[PayloadEncryptionService.Prefix.Length..]);
        raw[^1] ^= 0xFF;
        string corrupted = PayloadEncryptionService.Prefix + Base64Url.Encode(raw);

        var result = _verifier.Verify(corrupted);

        Assert.IsTrue(result.Status is VerificationStatus.DecryptionFailed or VerificationStatus.InvalidPayload);
        Assert.IsFalse(result.IsCryptographicallyValid);
        Assert.IsTrue(result.IsEncrypted);
    }

    [TestMethod]
    public void AuthenticityVerifier_Attack1_TamperedDocumentInsideEncryption_ReturnsInvalidSignature()
    {
        var docOriginal = new DocumentData("DOC-ORIGINAL", "Оригинальный Владелец", new DateOnly(2026, 1, 1), null);
        var signed = _creator.Create(docOriginal, _trustedRsa);

        var tamperedDoc = new DocumentData("DOC-HACKED-999", "Оригинальный Владелец", new DateOnly(2026, 1, 1), null);
        var tamperedSigned = new SignedPayload(signed.Version, signed.Algorithm, signed.KeyId, tamperedDoc, signed.Signature);
        var tamperedJson = new PayloadCodec().Encode(tamperedSigned);
        var tamperedEncrypted = _encryptionService.Encrypt(tamperedJson);

        var result = _verifier.Verify(tamperedEncrypted);

        Assert.AreEqual(VerificationStatus.InvalidSignature, result.Status);
        Assert.IsFalse(result.IsCryptographicallyValid);
        Assert.IsTrue(result.IsEncrypted);
    }

    [TestMethod]
    public void AuthenticityVerifier_Attack2_UntrustedKeyInsideEncryption_ReturnsUnknownKey()
    {
        var doc = new DocumentData("DOC-ATTACK-2", "Подставной Издатель", new DateOnly(2026, 1, 1), null);
        var encryptedWithUntrustedKey = _creator.CreateEncryptedPayload(doc, _attackerRsa);

        var result = _verifier.Verify(encryptedWithUntrustedKey);

        Assert.AreEqual(VerificationStatus.UnknownKey, result.Status);
        Assert.IsFalse(result.IsCryptographicallyValid);
        Assert.IsTrue(result.IsEncrypted);
    }
}
