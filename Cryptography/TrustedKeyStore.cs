using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using QrAuthenticity.Models;

namespace QrAuthenticity.Cryptography;

/// <summary>
/// Локальное хранилище доверенных открытых ключей издателей.
/// Проверяющая сторона доверяет подписи ТОЛЬКО в том случае, если открытый ключ
/// был предварительно явно добавлен в это хранилище доверия.
/// </summary>
public sealed class TrustedKeyStore : IDisposable
{
    private readonly Dictionary<string, (RSA Key, TrustedKeyEntry Entry)> _entries = new(StringComparer.OrdinalIgnoreCase);
    private readonly KeyManager _keyManager = new();
    private int _nextId = 1;

    /// <summary>
    /// Добавляет открытый ключ в доверенное хранилище.
    /// </summary>
    public TrustedKeyEntry AddPublicKey(string pem, string name = "Доверенный издатель")
    {
        var rsa = _keyManager.ImportPublicPem(pem);
        var keyId = _keyManager.ComputeKeyId(rsa);

        int id;
        if (_entries.Remove(keyId, out var old))
        {
            id = old.Entry.Id;
            old.Key.Dispose();
        }
        else
        {
            id = _nextId++;
        }

        var entry = new TrustedKeyEntry(id, keyId, name, DateTime.Now, pem);
        _entries[keyId] = (rsa, entry);
        return entry;
    }

    /// <summary>
    /// Удаляет ключ из доверенного хранилища.
    /// </summary>
    public bool Remove(string keyId)
    {
        if (_entries.Remove(keyId, out var removed))
        {
            removed.Key.Dispose();
            return true;
        }
        return false;
    }

    /// <summary>
    /// Обновляет имя/издателя для доверенного ключа.
    /// </summary>
    public bool UpdateName(string keyId, string newName)
    {
        if (_entries.TryGetValue(keyId, out var pair))
        {
            var updated = pair.Entry with { Name = newName };
            _entries[keyId] = (pair.Key, updated);
            return true;
        }
        return false;
    }

    /// <summary>
    /// Пытается получить объект RSA доверенного ключа по его идентификатору (Key ID).
    /// </summary>
    public bool TryGet(string keyId, out RSA? rsa)
    {
        if (_entries.TryGetValue(keyId, out var pair))
        {
            rsa = pair.Key;
            return true;
        }
        rsa = null;
        return false;
    }

    /// <summary>
    /// Возвращает список метаданных всех доверенных ключей.
    /// </summary>
    public IReadOnlyList<TrustedKeyEntry> GetAllEntries() => _entries.Values.Select(v => v.Entry).OrderBy(e => e.Id).ToList();

    public IReadOnlyCollection<string> KeyIds => _entries.Keys;

    /// <summary>
    /// Очищает хранилище и освобождает криптографические ресурсы.
    /// </summary>
    public void Dispose()
    {
        foreach (var pair in _entries.Values)
        {
            pair.Key.Dispose();
        }
        _entries.Clear();
    }
}
