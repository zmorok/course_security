using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using QrAuthenticity.Cryptography;
using QrAuthenticity.Models;
using QrAuthenticity.Serialization;
using QrAuthenticity.Services;
using QrAuthenticity.Verification;

namespace QrAuthenticity.Tests;

[TestClass]
public sealed class VerificationTests
{
    private static KeyManager _keyManager = null!;
    private static RSA _trustedRsa = null!;
    private static RSA _unknownRsa = null!;
    private static string _trustedPublicPem = null!;

    private TrustedKeyStore _trustedKeys = null!;
    private PayloadCodec _codec = null!;
    private PayloadCanonicalizer _canonicalizer = null!;
    private SignatureService _signatureService = null!;
    private PayloadCreationService _creator = null!;
    private AuthenticityVerifier _verifier = null!;

    [ClassInitialize]
    public static void ClassSetup(TestContext _)
    {
        _keyManager = new KeyManager();
        _trustedRsa = _keyManager.GenerateRsa(2048);
        _unknownRsa = _keyManager.GenerateRsa(2048);
        _trustedPublicPem = _keyManager.ExportPublicPem(_trustedRsa);
    }

    [ClassCleanup]
    public static void ClassCleanup()
    {
        _trustedRsa.Dispose();
        _unknownRsa.Dispose();
    }

    [TestInitialize]
    public void Setup()
    {
        _trustedKeys = new TrustedKeyStore();
        _trustedKeys.AddPublicKey(_trustedPublicPem, "Доверенный издатель");
        _codec = new PayloadCodec();
        _canonicalizer = new PayloadCanonicalizer();
        _signatureService = new SignatureService();
        _creator = new PayloadCreationService(_keyManager, _signatureService, _canonicalizer, _codec);
        _verifier = new AuthenticityVerifier(_codec, _canonicalizer, _signatureService, _trustedKeys);
    }

    [TestCleanup]
    public void Cleanup()
    {
        _trustedKeys.Dispose();
    }

    [TestMethod]
    public void Verify_ValidPayload_CoversActiveBoundaryAndPerpetualDocuments()
    {
        var docWithExpiry = new DocumentData("DOC-2026-001", "Алексей Смирнов", new DateOnly(2026, 1, 1), new DateOnly(2027, 1, 1));
        var json = _creator.CreateJson(docWithExpiry, _trustedRsa);

        var activeResult = _verifier.Verify(json, today: new DateOnly(2026, 6, 1));
        Assert.AreEqual(VerificationStatus.Valid, activeResult.Status);
        Assert.IsTrue(activeResult.IsCryptographicallyValid);
        Assert.IsFalse(activeResult.IsEncrypted);
        Assert.AreEqual("DOC-2026-001", activeResult.Payload?.Data.DocumentNumber);

        // В день окончания срока документ еще действителен (Expired только при Expires < today).
        var boundaryResult = _verifier.Verify(json, today: new DateOnly(2027, 1, 1));
        Assert.AreEqual(VerificationStatus.Valid, boundaryResult.Status);

        var perpetualDoc = new DocumentData("DOC-PERPETUAL", "Алексей Смирнов", new DateOnly(2026, 1, 1), null);
        var perpetualResult = _verifier.Verify(_creator.CreateJson(perpetualDoc, _trustedRsa), today: new DateOnly(2099, 12, 31));
        Assert.AreEqual(VerificationStatus.Valid, perpetualResult.Status);
    }

    [TestMethod]
    public void Verify_LegacyIsoDateSignature_SucceedsViaCanonicalizeLegacyFallback()
    {
        var data = new DocumentData("DOC-LEGACY-01", "Иван Иванов", new DateOnly(2026, 5, 1), new DateOnly(2030, 5, 1));
        string keyId = _keyManager.ComputeKeyId(_trustedRsa);
        var unsigned = new UnsignedPayload(1, SignatureService.AlgorithmName, keyId, data);

        byte[] legacyBytes = _canonicalizer.CanonicalizeLegacy(unsigned);
        byte[] signature = _signatureService.Sign(legacyBytes, _trustedRsa);

        string legacyJson =
            $"{{\"v\":1,\"alg\":\"{SignatureService.AlgorithmName}\",\"kid\":\"{keyId}\"," +
            "\"data\":{\"document\":\"DOC-LEGACY-01\",\"owner\":\"Иван Иванов\",\"issued\":\"2026-05-01\",\"expires\":\"2030-05-01\"}," +
            $"\"signature\":\"{Base64Url.Encode(signature)}\"}}";

        var result = _verifier.Verify(legacyJson, today: new DateOnly(2026, 6, 1));

        Assert.AreEqual(VerificationStatus.Valid, result.Status);
        Assert.IsTrue(result.IsCryptographicallyValid);
        Assert.AreEqual("DOC-LEGACY-01", result.Payload?.Data.DocumentNumber);
    }

    [TestMethod]
    public void Verify_TamperedDocumentFieldsOrSignature_ReturnsInvalidSignature()
    {
        var data = new DocumentData("DOC-2026-001", "Алексей Смирнов", new DateOnly(2026, 1, 1), new DateOnly(2027, 1, 1));
        var json = _creator.CreateJson(data, _trustedRsa);

        var docNode = JsonNode.Parse(json)!;
        docNode["data"]!["document"] = "DOC-2026-999";
        Assert.AreEqual(VerificationStatus.InvalidSignature, _verifier.Verify(docNode.ToJsonString()).Status);

        var ownerNode = JsonNode.Parse(json)!;
        ownerNode["data"]!["owner"] = "Злоумышленник";
        Assert.AreEqual(VerificationStatus.InvalidSignature, _verifier.Verify(ownerNode.ToJsonString()).Status);

        var dateNode = JsonNode.Parse(json)!;
        dateNode["data"]!["expires"] = "31.12.2030";
        Assert.AreEqual(VerificationStatus.InvalidSignature, _verifier.Verify(dateNode.ToJsonString()).Status);

        var sigNode = JsonNode.Parse(json)!;
        byte[] sigBytes = Base64Url.Decode(sigNode["signature"]!.GetValue<string>());
        sigBytes[0] ^= 0x55;
        sigNode["signature"] = Base64Url.Encode(sigBytes);
        var tamperedSigResult = _verifier.Verify(sigNode.ToJsonString());
        Assert.AreEqual(VerificationStatus.InvalidSignature, tamperedSigResult.Status);
        Assert.IsFalse(tamperedSigResult.IsCryptographicallyValid);
    }

    [TestMethod]
    public void Verify_UnknownKey_ReturnsUnknownKey()
    {
        var data = new DocumentData("DOC-100", "Иван Иванов", new DateOnly(2026, 1, 1), null);
        var json = _creator.CreateJson(data, _unknownRsa);

        var result = _verifier.Verify(json);

        Assert.AreEqual(VerificationStatus.UnknownKey, result.Status);
        Assert.IsFalse(result.IsCryptographicallyValid);
    }

    [TestMethod]
    public void Verify_ExpiredDocumentWithValidSignature_ReturnsExpired()
    {
        var data = new DocumentData("DOC-100", "Иван Иванов", new DateOnly(2025, 1, 1), new DateOnly(2025, 12, 31));
        var json = _creator.CreateJson(data, _trustedRsa);

        var result = _verifier.Verify(json, today: new DateOnly(2026, 9, 18));

        Assert.AreEqual(VerificationStatus.Expired, result.Status);
        Assert.IsTrue(result.IsCryptographicallyValid);
    }

    [TestMethod]
    public void Verify_UnsupportedVersionAndAlgorithm_ReturnExpectedStatuses()
    {
        var data = new DocumentData("DOC-100", "Иван Иванов", new DateOnly(2026, 1, 1), null);
        var json = _creator.CreateJson(data, _trustedRsa);

        var badVersion = JsonNode.Parse(json)!;
        badVersion["v"] = 2;
        Assert.AreEqual(VerificationStatus.UnsupportedVersion, _verifier.Verify(badVersion.ToJsonString()).Status);

        var badAlgorithm = JsonNode.Parse(json)!;
        badAlgorithm["alg"] = "RS256";
        Assert.AreEqual(VerificationStatus.UnsupportedAlgorithm, _verifier.Verify(badAlgorithm.ToJsonString()).Status);
    }

    [TestMethod]
    public void Verify_MalformedPayloads_ReturnInvalidPayload()
    {
        Assert.AreEqual(VerificationStatus.InvalidPayload, _verifier.Verify("").Status);
        Assert.AreEqual(VerificationStatus.InvalidPayload, _verifier.Verify("   ").Status);
        Assert.AreEqual(VerificationStatus.InvalidPayload, _verifier.Verify("not-a-json").Status);

        var data = new DocumentData("DOC-100", "Иван Иванов", new DateOnly(2026, 1, 1), new DateOnly(2027, 1, 1));
        var json = _creator.CreateJson(data, _trustedRsa);

        var badSignatureText = JsonNode.Parse(json)!;
        badSignatureText["signature"] = "!!!invalid-base64url!!!";
        Assert.AreEqual(VerificationStatus.InvalidPayload, _verifier.Verify(badSignatureText.ToJsonString()).Status);

        var invalidDateRange = JsonNode.Parse(json)!;
        invalidDateRange["data"]!["expires"] = "31.12.2025";
        Assert.AreEqual(VerificationStatus.InvalidPayload, _verifier.Verify(invalidDateRange.ToJsonString()).Status);
    }
}
