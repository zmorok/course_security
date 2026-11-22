using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using QrAuthenticity.Serialization;

namespace QrAuthenticity.Tests;

[TestClass]
public sealed class Base64UrlTests
{
    [DataTestMethod]
    [DataRow(0)]
    [DataRow(1)]
    [DataRow(2)]
    [DataRow(3)]
    [DataRow(4)]
    [DataRow(15)]
    [DataRow(32)]
    [DataRow(64)]
    [DataRow(256)]
    public void Base64Url_RoundTrip_SucceedsForAllLengths(int length)
    {
        var original = new byte[length];
        RandomNumberGenerator.Fill(original);

        var encoded = Base64Url.Encode(original);

        Assert.IsFalse(encoded.Contains('+'), "Base64Url must not contain '+'");
        Assert.IsFalse(encoded.Contains('/'), "Base64Url must not contain '/'");
        Assert.IsFalse(encoded.Contains('='), "Base64Url must not contain '='");

        var decoded = Base64Url.Decode(encoded);
        CollectionAssert.AreEqual(original, decoded);
    }

    [TestMethod]
    public void Base64Url_Encode_ReplacesPlusAndSlashWithUrlSafeCharacters()
    {
        byte[] sample = [0xFB, 0xFF, 0xFE];

        var encoded = Base64Url.Encode(sample);

        Assert.AreEqual("-__-", encoded);
        CollectionAssert.AreEqual(sample, Base64Url.Decode(encoded));
    }

    [TestMethod]
    public void Base64Url_Decode_EmptyReturnsEmptyArray()
    {
        var result = Base64Url.Decode("");
        Assert.IsNotNull(result);
        Assert.AreEqual(0, result.Length);
    }

    [TestMethod]
    public void Base64Url_Decode_NullThrowsArgumentNullException()
    {
        Assert.ThrowsException<ArgumentNullException>(() => Base64Url.Decode(null!));
    }

    [TestMethod]
    public void Base64Url_Decode_WhitespaceInvalidCharsOrInvalidLengthThrowsFormatException()
    {
        Assert.ThrowsException<FormatException>(() => Base64Url.Decode("   "));
        Assert.ThrowsException<FormatException>(() => Base64Url.Decode("invalid!@#$"));
        Assert.ThrowsException<FormatException>(() => Base64Url.Decode("A"));
    }
}
