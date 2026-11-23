using System.Diagnostics;
using System.Windows.Media.Imaging;
using QrAuthenticity.Models;
using QrAuthenticity.QR;
using QrAuthenticity.Verification;

namespace QrAuthenticity.Experiments;

/// <summary>
/// Сервис проведения серий экспериментов по оценке устойчивости
/// распознавания QR-кода и валидации цифровой подписи при искажениях.
/// </summary>
public sealed class ExperimentRunner
{
    private readonly ImageDistortionService _distortions;
    private readonly QrCodeService _qr;
    private readonly AuthenticityVerifier _verifier;

    public ExperimentRunner(ImageDistortionService distortions, QrCodeService qr, AuthenticityVerifier verifier)
    {
        _distortions = distortions;
        _qr = qr;
        _verifier = verifier;
    }

    /// <summary>
    /// Выполняет серию испытаний для одной точки интенсивности.
    /// </summary>
    public ExperimentResult RunPoint(
        BitmapSource source,
        string distortion,
        double intensity,
        int attempts = 10,
        int baseSeed = 42,
        CancellationToken cancellationToken = default)
    {
        if (attempts <= 0)
            return new ExperimentResult(distortion, intensity, 0, 0, 0, 0) { Seed = baseSeed };

        int decodeSuccesses = 0;
        int validSignatures = 0;
        double totalMilliseconds = 0;

        for (int i = 0; i < attempts; i++)
        {
            if (cancellationToken.IsCancellationRequested)
                break;

            int seed = baseSeed + i * 17;
            var distortedImage = _distortions.Apply(source, distortion, intensity, seed);

            var stopwatch = Stopwatch.StartNew();
            var decodedText = _qr.Decode(distortedImage);
            stopwatch.Stop();

            totalMilliseconds += stopwatch.Elapsed.TotalMilliseconds;

            if (decodedText is null)
                continue;

            decodeSuccesses++;

            var verification = _verifier.Verify(decodedText);
            if (verification.IsCryptographicallyValid)
            {
                validSignatures++;
            }
        }

        double averageDecodeMs = totalMilliseconds / attempts;
        return new ExperimentResult(distortion, intensity, attempts, decodeSuccesses, validSignatures, averageDecodeMs)
        {
            Seed = baseSeed
        };
    }

    /// <summary>
    /// Выполняет автоматическую серию экспериментов по всему диапазону интенсивности.
    /// </summary>
    public List<ExperimentResult> RunSeries(
        BitmapSource source,
        string distortion,
        double startIntensity,
        double endIntensity,
        double stepIntensity,
        int attemptsPerPoint = 10,
        int baseSeed = 42,
        Action<int, int, ExperimentResult>? onProgress = null,
        CancellationToken cancellationToken = default)
    {
        var results = new List<ExperimentResult>();

        if (stepIntensity <= 0)
            stepIntensity = 1.0;

        int totalSteps = (int)Math.Max(1, Math.Floor((endIntensity - startIntensity) / stepIntensity) + 1);
        int currentStep = 0;

        for (double intensity = startIntensity; intensity <= endIntensity + (stepIntensity * 0.01); intensity += stepIntensity)
        {
            if (cancellationToken.IsCancellationRequested)
                break;

            currentStep++;
            var pointResult = RunPoint(source, distortion, Math.Round(intensity, 2), attemptsPerPoint, baseSeed, cancellationToken);
            if (cancellationToken.IsCancellationRequested)
                break;

            results.Add(pointResult);

            onProgress?.Invoke(currentStep, totalSteps, pointResult);
        }

        return results;
    }
}
