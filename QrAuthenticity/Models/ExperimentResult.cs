namespace QrAuthenticity.Models;

/// <summary>
/// Результат одной экспериментальной точки испытаний помехоустойчивости QR-кода.
/// </summary>
public sealed record ExperimentResult(
    string Distortion,
    double Intensity,
    int Attempts,
    int DecodeSuccesses,
    int ValidSignatures,
    double AverageDecodeMilliseconds)
{
    /// <summary>
    /// Seed генератора случайных чисел, с которым выполнялось испытание.
    /// </summary>
    public int Seed { get; init; } = 42;

    /// <summary>
    /// Вероятность успешного распознавания QR-кода декодером (0.0 .. 1.0).
    /// </summary>
    public double DecodeRate => Attempts == 0 ? 0 : (double)DecodeSuccesses / Attempts;

    /// <summary>
    /// Вероятность сохранения подлинности и целостности данных (0.0 .. 1.0).
    /// </summary>
    public double ValidRate => Attempts == 0 ? 0 : (double)ValidSignatures / Attempts;
}
