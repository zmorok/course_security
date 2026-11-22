using System.IO;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using QrAuthenticity.Cryptography;

namespace QrAuthenticity.Tests;

[TestClass]
public sealed class TrustedKeyStoreTests
{
    private static KeyManager _keyManager = null!;
    private static RSA _rsa1 = null!;
    private static RSA _rsa2 = null!;
    private static string _pubPem1 = null!;
    private static string _pubPem2 = null!;
    private static string _privPem1 = null!;
    private static string _keyId1 = null!;
    private static string _keyId2 = null!;

    [ClassInitialize]
    public static void ClassSetup(TestContext _)
    {
        _keyManager = new KeyManager();
        _rsa1 = _keyManager.GenerateRsa(2048);
        _rsa2 = _keyManager.GenerateRsa(2048);
        _pubPem1 = _keyManager.ExportPublicPem(_rsa1);
        _pubPem2 = _keyManager.ExportPublicPem(_rsa2);
        _privPem1 = _keyManager.ExportPrivatePem(_rsa1);
        _keyId1 = _keyManager.ComputeKeyId(_rsa1);
        _keyId2 = _keyManager.ComputeKeyId(_rsa2);
    }

    [ClassCleanup]
    public static void ClassCleanup()
    {
        _rsa1.Dispose();
        _rsa2.Dispose();
    }

    [TestMethod]
    public void AddPublicKey_AssignsAutoIncrementId_AndPreservesIdOnReAdd()
    {
        using var store = new TrustedKeyStore();

        var entry1 = store.AddPublicKey(_pubPem1, "Издатель 1");
        var entry2 = store.AddPublicKey(_pubPem2, "Издатель 2");

        Assert.AreEqual(1, entry1.Id);
        Assert.AreEqual(2, entry2.Id);
        Assert.AreEqual("Издатель 1", entry1.Name);
        Assert.AreEqual(_keyId1, entry1.KeyId);
        Assert.AreEqual(_keyId2, entry2.KeyId);

        var updatedEntry1 = store.AddPublicKey(_pubPem1, "Издатель 1 (обновлён)");
        Assert.AreEqual(entry1.Id, updatedEntry1.Id);
        Assert.AreEqual(entry1.AddedAt, updatedEntry1.AddedAt);
        Assert.AreEqual("Издатель 1 (обновлён)", updatedEntry1.Name);
        Assert.AreEqual(2, store.GetAllEntries().Count);
    }

    [TestMethod]
    public void TryGet_IsCaseInsensitive_AndUpdateNameHandlesMissingKeys()
    {
        using var store = new TrustedKeyStore();
        store.AddPublicKey(_pubPem1, "Издатель 1");

        Assert.IsTrue(store.TryGet(_keyId1.ToLowerInvariant(), out var resolved));
        Assert.IsNotNull(resolved);
        Assert.IsFalse(store.TryGet("0000000000000000", out var missing));
        Assert.IsNull(missing);

        Assert.IsTrue(store.UpdateName(_keyId1, "Новое имя издателя"));
        Assert.IsFalse(store.UpdateName("0000000000000000", "Несуществующий"));

        var entries = store.GetAllEntries();
        Assert.AreEqual(1, entries.Count);
        Assert.AreEqual("Новое имя издателя", entries[0].Name);
    }

    [TestMethod]
    public void Persistence_SavesReloadsAndRemovesKeysFromDisk()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "qr_auth_store_test_" + Guid.NewGuid().ToString("N"));
        try
        {
            using (var store1 = new TrustedKeyStore(persist: true, customBaseDir: tempDir))
            {
                store1.SavePrivateKey(_keyId1, _privPem1);
                store1.AddPublicKey(_pubPem1, "Тестовый эмитент");
            }

            using (var store2 = new TrustedKeyStore(persist: true, customBaseDir: tempDir))
            {
                var entries = store2.GetAllEntries();
                Assert.AreEqual(1, entries.Count);
                Assert.AreEqual(_keyId1, entries[0].KeyId);
                Assert.AreEqual("Тестовый эмитент", entries[0].Name);

                Assert.IsTrue(store2.TryGetPrivateKeyPem(_keyId1, out var reloadedPrivate));
                Assert.AreEqual(_privPem1, reloadedPrivate);

                Assert.IsTrue(store2.Remove(_keyId1));
                Assert.IsFalse(store2.Remove(_keyId1));
                Assert.AreEqual(0, store2.GetAllEntries().Count);
                Assert.IsFalse(store2.TryGetPrivateKeyPem(_keyId1, out _));
            }

            using (var store3 = new TrustedKeyStore(persist: true, customBaseDir: tempDir))
            {
                Assert.AreEqual(0, store3.GetAllEntries().Count);
            }
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                try { Directory.Delete(tempDir, recursive: true); } catch { }
            }
        }
    }
}
