namespace QrAuthenticity.Models;

/// <summary>
/// Модель элемента выбора ключа для цифровой подписи QR-кода.
/// </summary>
public sealed record SigningKeyOption(
    string KeyId,
    string Name,
    int KeySize,
    string PublicPem)
{
    /// <summary>
    /// Отображаемый формат: Название • Идентификатор
    /// </summary>
    public string DisplayText => $"{Name} • {KeyId}";

    public override string ToString() => DisplayText;
}
