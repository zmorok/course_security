using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using QrAuthenticity.Cryptography;

namespace QrAuthenticity.Tests;

[TestClass]
public sealed class CryptographyTests
{
    private static KeyManager _keyManager = null!;
    private static RSA _sharedRsa = null!;
    private static RSA _otherRsa = null!;
    private static SignatureService _signer = null!;

    [ClassInitialize]
    public static void ClassSetup(TestContext _)
    {
        _keyManager = new KeyManager();
        _sharedRsa = _keyManager.GenerateRsa(2048);
        _otherRsa = _keyManager.GenerateRsa(2048);
        _signer = new SignatureService();
    }

    [ClassCleanup]
    public static void ClassCleanup()
    {
        _sharedRsa.Dispose();
        _otherRsa.Dispose();
    }

    [TestMethod]
    public void KeyManager_GeneratesRsa2048And3072_AndRejectsWeakKeys()
    {
        Assert.AreEqual(2048, _sharedRsa.KeySize);

        var keyId = _keyManager.ComputeKeyId(_sharedRsa);
        Assert.AreEqual(16, keyId.Length);
        Assert.IsTrue(keyId.All(c => char.IsAsciiHexDigitUpper(c)), $"Key ID '{keyId}' должен состоять из 16 hex-символов в верхнем регистре.");

        using var rsa3072 = _keyManager.GenerateRsa(3072);
        Assert.AreEqual(3072, rsa3072.KeySize);
        Assert.AreEqual(16, _keyManager.ComputeKeyId(rsa3072).Length);

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => _keyManager.GenerateRsa(1024));
    }

    [TestMethod]
    public void KeyManager_ExportAndImportPem_RoundTripAndDiskSave()
    {
        var keyIdOriginal = _keyManager.ComputeKeyId(_sharedRsa);

        var privatePem = _keyManager.ExportPrivatePem(_sharedRsa);
        var publicPem = _keyManager.ExportPublicPem(_sharedRsa);

        Assert.IsTrue(privatePem.Contains("BEGIN PRIVATE KEY", StringComparison.Ordinal));
        Assert.IsTrue(publicPem.Contains("BEGIN PUBLIC KEY", StringComparison.Ordinal));

        using var importedPrivate = _keyManager.ImportPrivatePem(privatePem);
        using var importedPublic = _keyManager.ImportPublicPem(publicPem);

        Assert.AreEqual(keyIdOriginal, _keyManager.ComputeKeyId(importedPrivate));
        Assert.AreEqual(keyIdOriginal, _keyManager.ComputeKeyId(importedPublic));

        string tempDir = Path.Combine(Path.GetTempPath(), "qr_auth_pem_test_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            string pubPath = Path.Combine(tempDir, "public.pem");
            string privPath = Path.Combine(tempDir, "private.pem");

            _keyManager.SavePublicPem(_sharedRsa, pubPath);
            _keyManager.SavePrivatePem(_sharedRsa, privPath);

            using var loadedPub = _keyManager.ImportPublicPem(File.ReadAllText(pubPath));
            using var loadedPriv = _keyManager.ImportPrivatePem(File.ReadAllText(privPath));

            Assert.AreEqual(keyIdOriginal, _keyManager.ComputeKeyId(loadedPub));
            Assert.AreEqual(keyIdOriginal, _keyManager.ComputeKeyId(loadedPriv));
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                try { Directory.Delete(tempDir, recursive: true); } catch { }
            }
        }
    }

    [TestMethod]
    public void SignatureService_SignAndVerify_ValidDataUsesProbabilisticPssAndSucceeds()
    {
        Assert.AreEqual("RSA-PSS-SHA256", SignatureService.AlgorithmName);

        var data = Encoding.UTF8.GetBytes("Test string for digital signature verification");

        var signature1 = _signer.Sign(data, _sharedRsa);
        var signature2 = _signer.Sign(data, _sharedRsa);

        Assert.AreEqual(256, signature1.Length);
        CollectionAssert.AreNotEqual(signature1, signature2, "RSA-PSS использует случайную соль, поэтому повторные подписи должны различаться.");

        Assert.IsTrue(_signer.Verify(data, signature1, _sharedRsa));
        Assert.IsTrue(_signer.Verify(data, signature2, _sharedRsa));
    }

    [TestMethod]
    public void SignatureService_TamperedDataSignatureOrWrongKey_FailsVerification()
    {
        var data = Encoding.UTF8.GetBytes("Test string for digital signature verification");
        var signature = _signer.Sign(data, _sharedRsa);

        var tamperedData = (byte[])data.Clone();
        tamperedData[0] ^= 0x01;
        Assert.IsFalse(_signer.Verify(tamperedData, signature, _sharedRsa), "Подпись должна отвергаться при изменении хотя бы 1 бита данных.");

        var tamperedSignature = (byte[])signature.Clone();
        tamperedSignature[10] ^= 0x80;
        Assert.IsFalse(_signer.Verify(data, tamperedSignature, _sharedRsa), "Подпись должна отвергаться при ее модификации.");

        Assert.IsFalse(_signer.Verify(data, signature, _otherRsa), "Подпись не должна проверяться чужим открытым ключом.");
    }
}
