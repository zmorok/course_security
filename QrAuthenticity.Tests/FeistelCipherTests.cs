using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using QrAuthenticity.Cryptography;

namespace QrAuthenticity.Tests;

[TestClass]
public sealed class FeistelCipherTests
{
    private static readonly byte[] TestKey = Encoding.UTF8.GetBytes("Test-Secret-Key-Feistel-2026");

    [TestMethod]
    public void FeistelCipher_SingleBlock_EncryptAndDecrypt_MatchesOriginal()
    {
        var cipher = new FeistelCipher(TestKey);
        byte[] original = Encoding.UTF8.GetBytes("0123456789ABCDEF");
        byte[] encrypted = new byte[FeistelCipher.BlockSize];
        byte[] decrypted = new byte[FeistelCipher.BlockSize];

        cipher.EncryptBlock(original, encrypted);
        cipher.DecryptBlock(encrypted, decrypted);

        CollectionAssert.AreEqual(original, decrypted);
        CollectionAssert.AreNotEqual(original, encrypted);
    }

    [DataTestMethod]
    [DataRow(0)]
    [DataRow(1)]
    [DataRow(7)]
    [DataRow(15)]
    [DataRow(16)]
    [DataRow(17)]
    [DataRow(32)]
    [DataRow(255)]
    [DataRow(1024)]
    public void FeistelCipher_CbcMode_ArbitraryLengths_RoundTripSucceeds(int length)
    {
        var cipher = new FeistelCipher(TestKey);
        byte[] plaintext = new byte[length];
        for (int i = 0; i < length; i++)
        {
            plaintext[i] = (byte)((i * 31 + 17) & 0xFF);
        }

        byte[] iv = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        byte[] ciphertext = cipher.EncryptCbc(plaintext, iv);
        Assert.AreEqual(0, ciphertext.Length % FeistelCipher.BlockSize);
        Assert.IsTrue(ciphertext.Length > plaintext.Length);

        byte[] decrypted = cipher.DecryptCbc(ciphertext, iv);
        CollectionAssert.AreEqual(plaintext, decrypted);
    }

    [TestMethod]
    public void FeistelCipher_CbcMode_DifferentIv_ProducesDifferentCiphertext()
    {
        var cipher = new FeistelCipher(TestKey);
        byte[] plaintext = Encoding.UTF8.GetBytes("Document authentication secret payload test.");

        byte[] iv1 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        byte[] iv2 = [15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0];

        byte[] cipher1 = cipher.EncryptCbc(plaintext, iv1);
        byte[] cipher2 = cipher.EncryptCbc(plaintext, iv2);

        CollectionAssert.AreNotEqual(cipher1, cipher2, "Одинаковый открытый текст с разными IV должен давать разный шифротекст.");
    }

    [TestMethod]
    public void FeistelCipher_AvalancheEffect_SingleBitChangeInPlaintext_FlipsAroundHalfBits()
    {
        var cipher = new FeistelCipher(TestKey);
        int totalChangedBits = 0;
        const int sampleCount = 16;

        for (int sample = 0; sample < sampleCount; sample++)
        {
            byte[] block1 = new byte[FeistelCipher.BlockSize];
            for (int b = 0; b < FeistelCipher.BlockSize; b++)
            {
                block1[b] = (byte)((sample * 37 + b * 19 + 5) & 0xFF);
            }

            byte[] block2 = (byte[])block1.Clone();
            block2[sample % FeistelCipher.BlockSize] ^= (byte)(1 << (sample % 8));

            byte[] cipher1 = new byte[FeistelCipher.BlockSize];
            byte[] cipher2 = new byte[FeistelCipher.BlockSize];

            cipher.EncryptBlock(block1, cipher1);
            cipher.EncryptBlock(block2, cipher2);

            int changedBits = 0;
            for (int i = 0; i < FeistelCipher.BlockSize; i++)
            {
                changedBits += BitOperations.PopCount((uint)(cipher1[i] ^ cipher2[i]));
            }

            Assert.IsTrue(changedBits >= 35, $"Для образца {sample} изменилось слишком мало бит: {changedBits} из 128.");
            totalChangedBits += changedBits;
        }

        double averageChangedBits = (double)totalChangedBits / sampleCount;
        Assert.IsTrue(averageChangedBits >= 54.0 && averageChangedBits <= 74.0,
            $"Средний лавинный эффект: {averageChangedBits:F2} из 128 бит (ожидается ~64).");
    }

    [TestMethod]
    public void FeistelCipher_WrongKey_ThrowsOrFailsToRecoverPlaintext()
    {
        var cipher1 = new FeistelCipher(Encoding.UTF8.GetBytes("Correct-Key-12345"));
        var cipher2 = new FeistelCipher(Encoding.UTF8.GetBytes("Wrong-Key-9999999"));

        byte[] plaintext = Encoding.UTF8.GetBytes("Confident document data for testing cryptographic failure.");
        byte[] iv = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160];

        byte[] ciphertext = cipher1.EncryptCbc(plaintext, iv);

        try
        {
            byte[] decrypted = cipher2.DecryptCbc(ciphertext, iv);
            CollectionAssert.AreNotEqual(plaintext, decrypted);
        }
        catch (CryptographicException)
        {
            Assert.IsTrue(true);
        }
    }

    [TestMethod]
    public void FeistelCipher_TamperedCiphertextLastBlock_ThrowsOrFailsToRecoverPlaintext()
    {
        var cipher = new FeistelCipher(TestKey);
        byte[] plaintext = Encoding.UTF8.GetBytes("Deterministic payload for CBC padding integrity check.");
        byte[] iv = [1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31];

        byte[] ciphertext = cipher.EncryptCbc(plaintext, iv);
        ciphertext[^1] ^= 0x01;

        try
        {
            byte[] decrypted = cipher.DecryptCbc(ciphertext, iv);
            CollectionAssert.AreNotEqual(plaintext, decrypted);
        }
        catch (CryptographicException)
        {
            Assert.IsTrue(true);
        }
    }

    [TestMethod]
    public void FeistelCipher_InvalidArguments_ThrowExpectedExceptions()
    {
        Assert.ThrowsException<ArgumentException>(() => new FeistelCipher(null!));
        Assert.ThrowsException<ArgumentException>(() => new FeistelCipher(Array.Empty<byte>()));

        var cipher = new FeistelCipher(TestKey);
        byte[] shortBlock = new byte[15];
        byte[] validBlock = new byte[16];

        Assert.ThrowsException<ArgumentException>(() => cipher.EncryptBlock(shortBlock, validBlock));
        Assert.ThrowsException<ArgumentException>(() => cipher.EncryptBlock(validBlock, shortBlock));
        Assert.ThrowsException<ArgumentException>(() => cipher.DecryptBlock(shortBlock, validBlock));
        Assert.ThrowsException<ArgumentException>(() => cipher.DecryptBlock(validBlock, shortBlock));

        Assert.ThrowsException<ArgumentException>(() => cipher.EncryptCbc(validBlock, shortBlock));
        Assert.ThrowsException<ArgumentException>(() => cipher.DecryptCbc(validBlock, shortBlock));
        Assert.ThrowsException<CryptographicException>(() => cipher.DecryptCbc(Array.Empty<byte>(), validBlock));
        Assert.ThrowsException<CryptographicException>(() => cipher.DecryptCbc(new byte[17], validBlock));
    }
}
