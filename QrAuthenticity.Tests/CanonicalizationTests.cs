using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using QrAuthenticity.Cryptography;
using QrAuthenticity.Models;
using QrAuthenticity.Serialization;

namespace QrAuthenticity.Tests;

[TestClass]
public sealed class CanonicalizationTests
{
    [TestMethod]
    public void Canonicalize_ProducesDeterministicExactUtf8BytesWithRussianDates()
    {
        var canonicalizer = new PayloadCanonicalizer();
        var data = new DocumentData("DOC-12345", "Иван Иванов", new DateOnly(2026, 9, 1), new DateOnly(2030, 9, 1));
        var payload = new UnsignedPayload(1, SignatureService.AlgorithmName, "A1B2C3D4E5F67890", data);

        var bytes = canonicalizer.Canonicalize(payload);
        var json = Encoding.UTF8.GetString(bytes);

        const string expected = "{\"v\":1,\"alg\":\"RSA-PSS-SHA256\",\"kid\":\"A1B2C3D4E5F67890\",\"data\":{\"document\":\"DOC-12345\",\"owner\":\"Иван Иванов\",\"issued\":\"01.09.2026\",\"expires\":\"01.09.2030\"}}";
        Assert.AreEqual(expected, json);
    }

    [TestMethod]
    public void Canonicalize_TrimsWhitespaceAndHandlesNullExpires()
    {
        var canonicalizer = new PayloadCanonicalizer();
        var data = new DocumentData("  DOC-999  ", "  Петр Петров  ", new DateOnly(2026, 1, 15), null);
        var payload = new UnsignedPayload(1, SignatureService.AlgorithmName, "KEYID123", data);

        var bytes = canonicalizer.Canonicalize(payload);
        var json = Encoding.UTF8.GetString(bytes);

        const string expected = "{\"v\":1,\"alg\":\"RSA-PSS-SHA256\",\"kid\":\"KEYID123\",\"data\":{\"document\":\"DOC-999\",\"owner\":\"Петр Петров\",\"issued\":\"15.01.2026\",\"expires\":null}}";
        Assert.AreEqual(expected, json);
    }

    [TestMethod]
    public void CanonicalizeLegacy_ProducesIsoDatesAndHandlesNullExpires()
    {
        var canonicalizer = new PayloadCanonicalizer();
        var data = new DocumentData("DOC-12345", "Иван Иванов", new DateOnly(2026, 9, 1), new DateOnly(2030, 9, 1));
        var payload = new UnsignedPayload(1, SignatureService.AlgorithmName, "A1B2C3D4E5F67890", data);

        var json = Encoding.UTF8.GetString(canonicalizer.CanonicalizeLegacy(payload));
        const string expected = "{\"v\":1,\"alg\":\"RSA-PSS-SHA256\",\"kid\":\"A1B2C3D4E5F67890\",\"data\":{\"document\":\"DOC-12345\",\"owner\":\"Иван Иванов\",\"issued\":\"2026-09-01\",\"expires\":\"2030-09-01\"}}";
        Assert.AreEqual(expected, json);

        var noExpiryPayload = payload with { Data = data with { Expires = null } };
        var noExpiryJson = Encoding.UTF8.GetString(canonicalizer.CanonicalizeLegacy(noExpiryPayload));
        const string expectedNoExpiry = "{\"v\":1,\"alg\":\"RSA-PSS-SHA256\",\"kid\":\"A1B2C3D4E5F67890\",\"data\":{\"document\":\"DOC-12345\",\"owner\":\"Иван Иванов\",\"issued\":\"2026-09-01\",\"expires\":null}}";
        Assert.AreEqual(expectedNoExpiry, noExpiryJson);
    }

    [TestMethod]
    public void Canonicalize_InvalidDocument_ThrowsArgumentException()
    {
        var canonicalizer = new PayloadCanonicalizer();

        Assert.ThrowsException<ArgumentException>(() =>
            canonicalizer.Canonicalize(new UnsignedPayload(1, SignatureService.AlgorithmName, "KID",
                new DocumentData("   ", "Иван Иванов", new DateOnly(2026, 9, 1), null))));

        Assert.ThrowsException<ArgumentException>(() =>
            canonicalizer.Canonicalize(new UnsignedPayload(1, SignatureService.AlgorithmName, "KID",
                new DocumentData("DOC-1", "   ", new DateOnly(2026, 9, 1), null))));

        Assert.ThrowsException<ArgumentException>(() =>
            canonicalizer.Canonicalize(new UnsignedPayload(1, SignatureService.AlgorithmName, "KID",
                new DocumentData("DOC-1", "Иван Иванов", new DateOnly(2026, 9, 10), new DateOnly(2026, 9, 1)))));
    }

    [TestMethod]
    public void PayloadCodec_Encode_UsesRussianDatesWithoutEscapingCyrillic()
    {
        var codec = new PayloadCodec();
        var data = new DocumentData("ДОК-01", "Иванов Иван", new DateOnly(2026, 9, 18), new DateOnly(2031, 9, 18));
        var signed = new SignedPayload(1, SignatureService.AlgorithmName, "KEY1234567890ABC", data, "SIG_DATA");

        string json = codec.Encode(signed);

        Assert.IsTrue(json.Contains("Иванов Иван", StringComparison.Ordinal));
        Assert.IsTrue(json.Contains("\"issued\":\"18.09.2026\"", StringComparison.Ordinal));
        Assert.IsTrue(json.Contains("\"expires\":\"18.09.2031\"", StringComparison.Ordinal));
        Assert.IsFalse(json.Contains("\\u", StringComparison.Ordinal));
    }

    [TestMethod]
    public void PayloadCodec_Decode_ParsesRussianAndLegacyDatesAndEmptyExpires()
    {
        var codec = new PayloadCodec();

        string russianJson = "{\"v\":1,\"alg\":\"RSA-PSS-SHA256\",\"kid\":\"KID1\",\"data\":{\"document\":\"DOC-1\",\"owner\":\"Иван\",\"issued\":\"01.09.2026\",\"expires\":\"01.10.2026\"},\"signature\":\"SIG\"}";
        var russianDecoded = codec.Decode(russianJson);
        Assert.AreEqual(new DateOnly(2026, 9, 1), russianDecoded.Data.Issued);
        Assert.AreEqual(new DateOnly(2026, 10, 1), russianDecoded.Data.Expires);

        string legacyJson = "{\"v\":1,\"alg\":\"RSA-PSS-SHA256\",\"kid\":\"KID1\",\"data\":{\"document\":\"DOC-1\",\"owner\":\"Иван\",\"issued\":\"2026-09-01\",\"expires\":\"\"},\"signature\":\"SIG\"}";
        var legacyDecoded = codec.Decode(legacyJson);
        Assert.AreEqual(new DateOnly(2026, 9, 1), legacyDecoded.Data.Issued);
        Assert.IsNull(legacyDecoded.Data.Expires);

        string nullExpiresJson = "{\"v\":1,\"alg\":\"RSA-PSS-SHA256\",\"kid\":\"KID1\",\"data\":{\"document\":\"DOC-1\",\"owner\":\"Иван\",\"issued\":\"01.09.2026\",\"expires\":null},\"signature\":\"SIG\"}";
        var nullExpiresDecoded = codec.Decode(nullExpiresJson);
        Assert.IsNull(nullExpiresDecoded.Data.Expires);
    }

    [TestMethod]
    public void PayloadCodec_Decode_InvalidInputs_ThrowsExpectedExceptions()
    {
        var codec = new PayloadCodec();

        Assert.ThrowsException<FormatException>(() => codec.Decode("{not-json"));
        Assert.ThrowsException<FormatException>(() => codec.Decode("null"));
        Assert.ThrowsException<FormatException>(() =>
            codec.Decode("{\"v\":1,\"alg\":\"\",\"kid\":\"KID1\",\"data\":{\"document\":\"DOC-1\",\"owner\":\"Иван\",\"issued\":\"01.09.2026\",\"expires\":null},\"signature\":\"SIG\"}"));
        Assert.ThrowsException<FormatException>(() =>
            codec.Decode("{\"v\":1,\"alg\":\"RSA-PSS-SHA256\",\"kid\":\"KID1\",\"data\":{\"document\":\"DOC-1\",\"owner\":\"Иван\",\"issued\":\"bad-date\",\"expires\":null},\"signature\":\"SIG\"}"));
        Assert.ThrowsException<ArgumentException>(() =>
            codec.Decode("{\"v\":1,\"alg\":\"RSA-PSS-SHA256\",\"kid\":\"KID1\",\"data\":{\"document\":\"DOC-1\",\"owner\":\"Иван\",\"issued\":\"10.09.2026\",\"expires\":\"01.09.2026\"},\"signature\":\"SIG\"}"));
    }
}
