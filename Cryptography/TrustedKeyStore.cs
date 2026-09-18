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
    private readonly bool _persist;
    private readonly string? _storageDir;
    private readonly string? _metaFilePath;
    private readonly string? _privateKeysDir;
    private int _nextId = 1;

    public TrustedKeyStore(bool persist = false, string? customBaseDir = null)
    {
        _persist = persist;
        if (_persist)
        {
            var baseDir = customBaseDir ?? AppDomain.CurrentDomain.BaseDirectory;
            _storageDir = Path.Combine(baseDir, "trusted-keys");
            _metaFilePath = Path.Combine(_storageDir, "trusted_keys.json");
            _privateKeysDir = Path.Combine(baseDir, "private-keys");

            try
            {
                Directory.CreateDirectory(_storageDir);
                Directory.CreateDirectory(_privateKeysDir);
                LoadFromDisk();
            }
            catch
            {
                // Защита от ошибок ввода-вывода при инициализации каталогов
            }
        }
    }

    private void LoadFromDisk()
    {
        if (_metaFilePath is null || !File.Exists(_metaFilePath))
        {
            return;
        }

        try
        {
            var json = File.ReadAllText(_metaFilePath);
            var items = JsonSerializer.Deserialize<List<TrustedKeyEntry>>(json);
            if (items is null) return;

            foreach (var item in items)
            {
                try
                {
                    var rsa = _keyManager.ImportPublicPem(item.PublicPem);
                    _entries[item.KeyId] = (rsa, item);
                    if (item.Id >= _nextId)
                    {
                        _nextId = item.Id + 1;
                    }
                }
                catch
                {
                    // Пропуск некорректно сформированных записей
                }
            }
        }
        catch
        {
            // Игнорирование повреждений конфигурационного файла
        }
    }

    private void SaveToDisk()
    {
        if (!_persist || _metaFilePath is null) return;

        try
        {
            var list = _entries.Values.Select(v => v.Entry).OrderBy(e => e.Id).ToList();
            var json = JsonSerializer.Serialize(list, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_metaFilePath, json);
        }
        catch
        {
        }
    }

    /// <summary>
    /// Сохраняет закрытый ключ в локальное изолированное хранилище ключей.
    /// </summary>
    public void SavePrivateKey(string keyId, string privatePem)
    {
        if (!_persist || _privateKeysDir is null) return;

        try
        {
            var path = Path.Combine(_privateKeysDir, $"{keyId}.pem");
            File.WriteAllText(path, privatePem);
        }
        catch
        {
        }
    }

    /// <summary>
    /// Пытается прочитать закрытый ключ из локального хранилища ключей.
    /// </summary>
    public bool TryGetPrivateKeyPem(string keyId, out string? privatePem)
    {
        privatePem = null;
        if (_privateKeysDir is null) return false;

        var path = Path.Combine(_privateKeysDir, $"{keyId}.pem");
        if (File.Exists(path))
        {
            try
            {
                privatePem = File.ReadAllText(path);
                return true;
            }
            catch
            {
                return false;
            }
        }
        return false;
    }

    /// <summary>
    /// Добавляет открытый ключ в доверенное хранилище.
    /// </summary>
    public TrustedKeyEntry AddPublicKey(string pem, string name = "Доверенный издатель")
    {
        var rsa = _keyManager.ImportPublicPem(pem);
        var keyId = _keyManager.ComputeKeyId(rsa);

        int id;
        DateTime addedAt;

        if (_entries.Remove(keyId, out var old))
        {
            id = old.Entry.Id;
            addedAt = old.Entry.AddedAt;
            old.Key.Dispose();
        }
        else
        {
            id = _nextId++;
            addedAt = DateTime.Now;
        }

        var entry = new TrustedKeyEntry(id, keyId, name, addedAt, pem);
        _entries[keyId] = (rsa, entry);
        SaveToDisk();
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

            if (_persist && _privateKeysDir is not null)
            {
                try
                {
                    var privateKeyPath = Path.Combine(_privateKeysDir, $"{keyId}.pem");
                    if (File.Exists(privateKeyPath))
                    {
                        File.Delete(privateKeyPath);
                    }
                }
                catch
                {
                }
            }

            SaveToDisk();
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
            SaveToDisk();
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
