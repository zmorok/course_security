namespace QrAuthenticity.Models;

/// <summary>
/// Запись о доверенном открытом ключе издателя в локальном хранилище.
/// </summary>
public sealed record TrustedKeyEntry(
    int Id,
    string KeyId,
    string Name,
    DateTime AddedAt,
    string PublicPem);
