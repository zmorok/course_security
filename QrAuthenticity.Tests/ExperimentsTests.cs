using System.Security.Cryptography;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using QrAuthenticity.Cryptography;
using QrAuthenticity.Experiments;
using QrAuthenticity.Models;
using QrAuthenticity.QR;
using QrAuthenticity.Serialization;
using QrAuthenticity.Services;
using QrAuthenticity.Verification;
using ZXing.QrCode.Internal;

namespace QrAuthenticity.Tests;

[TestClass]
public sealed class ExperimentsTests
{
    private static KeyManager _keyManager = null!;
    private static RSA _rsa = null!;
    private static string _publicPem = null!;
    private static BitmapSource _sourceQr = null!;

    [ClassInitialize]
    public static void ClassSetup(TestContext _)
    {
        _keyManager = new KeyManager();
        _rsa = _keyManager.GenerateRsa(2048);
        _publicPem = _keyManager.ExportPublicPem(_rsa);

        StaTestHelper.Run(() =>
        {
            var encService = new PayloadEncryptionService();
            var creator = new PayloadCreationService(_keyManager, new SignatureService(), new PayloadCanonicalizer(), new PayloadCodec(), encService);
            var qrService = new QrCodeService();

            var data = new DocumentData("DOC-EXP-001", "Иван Экспериментов", new DateOnly(2026, 9, 1), new DateOnly(2031, 9, 1));
            string payload = creator.CreateEncryptedPayload(data, _rsa);
            _sourceQr = qrService.Generate(payload, pixels: 400, level: ErrorCorrectionLevel.Q);
        });
    }

    [ClassCleanup]
    public static void ClassCleanup()
    {
        _rsa.Dispose();
    }

    [TestMethod]
    public void ImageDistortionService_ZeroIntensityReturnsOriginal_AndAllSevenDistortionsProduceFrozenImages()
    {
        StaTestHelper.Run(() =>
        {
            var distortionService = new ImageDistortionService();

            Assert.AreEqual(7, ImageDistortionService.AvailableDistortions.Count);
            Assert.AreSame(_sourceQr, distortionService.Apply(_sourceQr, ImageDistortionService.DistortionNoise, 0.0));

            foreach (var distortion in ImageDistortionService.AvailableDistortions)
            {
                var distorted = distortionService.Apply(_sourceQr, distortion, intensity: 10.0, seed: 123);
                Assert.IsNotNull(distorted, $"Искажение '{distortion}' не должно возвращать null.");
                Assert.IsTrue(distorted.IsFrozen, $"Результат искажения '{distortion}' должен быть Frozen для использования в фоновых потоках.");
                Assert.IsTrue(distorted.PixelWidth > 0);
                Assert.IsTrue(distorted.PixelHeight > 0);
            }

            Assert.ThrowsException<ArgumentException>(() =>
                distortionService.Apply(_sourceQr, "Неизвестное искажение", intensity: 10.0));
        });
    }

    [TestMethod]
    public void ImageDistortionService_SeededDistortions_AreDeterministic()
    {
        StaTestHelper.Run(() =>
        {
            var distortionService = new ImageDistortionService();

            foreach (var distortion in new[] { ImageDistortionService.DistortionOcclusion, ImageDistortionService.DistortionNoise })
            {
                var first = distortionService.Apply(_sourceQr, distortion, intensity: 15.0, seed: 77);
                var second = distortionService.Apply(_sourceQr, distortion, intensity: 15.0, seed: 77);

                CollectionAssert.AreEqual(GetPixels(first), GetPixels(second), $"Искажение '{distortion}' должно быть детерминированным по seed.");
            }
        });
    }

    [TestMethod]
    public void ImageDistortionService_ValidRangesAndHighIntensities_ScaleMonotonicallyUpToMax()
    {
        StaTestHelper.Run(() =>
        {
            var distortionService = new ImageDistortionService();

            Assert.AreEqual((0.0, 360.0, "°"), ImageDistortionService.GetValidIntensityRange(ImageDistortionService.DistortionRotate));
            foreach (var distortion in ImageDistortionService.AvailableDistortions.Where(d => d != ImageDistortionService.DistortionRotate))
            {
                var range = ImageDistortionService.GetValidIntensityRange(distortion);
                Assert.AreEqual(0.0, range.Min);
                Assert.AreEqual(100.0, range.Max);
            }

            // Перекрытие пятном: 50%, 80% и 100% должны различаться
            var occ50 = GetPixels(distortionService.Apply(_sourceQr, ImageDistortionService.DistortionOcclusion, 50.0, seed: 42));
            var occ80 = GetPixels(distortionService.Apply(_sourceQr, ImageDistortionService.DistortionOcclusion, 80.0, seed: 42));
            var occ100 = GetPixels(distortionService.Apply(_sourceQr, ImageDistortionService.DistortionOcclusion, 100.0, seed: 42));
            Assert.IsFalse(occ50.SequenceEqual(occ80));
            Assert.IsFalse(occ80.SequenceEqual(occ100));

            // Импульсный шум: 50%, 80% и 100% должны различаться
            var noise50 = GetPixels(distortionService.Apply(_sourceQr, ImageDistortionService.DistortionNoise, 50.0, seed: 42));
            var noise80 = GetPixels(distortionService.Apply(_sourceQr, ImageDistortionService.DistortionNoise, 80.0, seed: 42));
            var noise100 = GetPixels(distortionService.Apply(_sourceQr, ImageDistortionService.DistortionNoise, 100.0, seed: 42));
            Assert.IsFalse(noise50.SequenceEqual(noise80));
            Assert.IsFalse(noise80.SequenceEqual(noise100));

            // Размытие: радиус 12, 30 и 100 должны различаться
            var blur12 = GetPixels(distortionService.Apply(_sourceQr, ImageDistortionService.DistortionBlur, 12.0));
            var blur30 = GetPixels(distortionService.Apply(_sourceQr, ImageDistortionService.DistortionBlur, 30.0));
            var blur100 = GetPixels(distortionService.Apply(_sourceQr, ImageDistortionService.DistortionBlur, 100.0));
            Assert.IsFalse(blur12.SequenceEqual(blur30));
            Assert.IsFalse(blur30.SequenceEqual(blur100));

            // Снижение разрешения: 90%, 95% и 100% должны различаться
            var scale90 = GetPixels(distortionService.Apply(_sourceQr, ImageDistortionService.DistortionScale, 90.0));
            var scale95 = GetPixels(distortionService.Apply(_sourceQr, ImageDistortionService.DistortionScale, 95.0));
            var scale100 = GetPixels(distortionService.Apply(_sourceQr, ImageDistortionService.DistortionScale, 100.0));
            Assert.IsFalse(scale90.SequenceEqual(scale95));
            Assert.IsFalse(scale95.SequenceEqual(scale100));

            // Сжатие JPEG: 50%, 80% и 100% должны различаться и усиливать деградацию
            var jpeg50 = GetPixels(distortionService.Apply(_sourceQr, ImageDistortionService.DistortionJpeg, 50.0));
            var jpeg80 = GetPixels(distortionService.Apply(_sourceQr, ImageDistortionService.DistortionJpeg, 80.0));
            var jpeg100 = GetPixels(distortionService.Apply(_sourceQr, ImageDistortionService.DistortionJpeg, 100.0));
            Assert.IsFalse(jpeg50.SequenceEqual(jpeg80));
            Assert.IsFalse(jpeg80.SequenceEqual(jpeg100));

            // Контраст: 100% дает однородный серый (128)
            var contrast100 = GetPixels(distortionService.Apply(_sourceQr, ImageDistortionService.DistortionContrast, 100.0));
            Assert.AreEqual(128, contrast100[0]);
            Assert.AreEqual(128, contrast100[1]);
            Assert.AreEqual(128, contrast100[2]);
        });
    }

    [TestMethod]
    public void ExperimentRunner_RunPointAndRunSeries_ComputeExpectedMetricsAndProgress()
    {
        StaTestHelper.Run(() =>
        {
            using var store = new TrustedKeyStore();
            store.AddPublicKey(_publicPem);

            var distortions = new ImageDistortionService();
            var qrService = new QrCodeService();
            var verifier = new AuthenticityVerifier(
                new PayloadCodec(),
                new PayloadCanonicalizer(),
                new SignatureService(),
                store,
                new PayloadEncryptionService());
            var runner = new ExperimentRunner(distortions, qrService, verifier);

            var zeroAttempts = runner.RunPoint(_sourceQr, ImageDistortionService.DistortionContrast, 0.0, attempts: 0);
            Assert.AreEqual(0, zeroAttempts.DecodeRate);
            Assert.AreEqual(0, zeroAttempts.ValidRate);

            var cleanPoint = runner.RunPoint(_sourceQr, ImageDistortionService.DistortionContrast, intensity: 0.0, attempts: 2);
            Assert.AreEqual(2, cleanPoint.Attempts);
            Assert.AreEqual(2, cleanPoint.DecodeSuccesses);
            Assert.AreEqual(2, cleanPoint.ValidSignatures);
            Assert.AreEqual(1.0, cleanPoint.DecodeRate);
            Assert.AreEqual(1.0, cleanPoint.ValidRate);
            Assert.IsTrue(cleanPoint.AverageDecodeMilliseconds >= 0);

            var reportedSteps = new List<(int Step, int Total, double Intensity)>();
            var series = runner.RunSeries(
                _sourceQr,
                ImageDistortionService.DistortionContrast,
                startIntensity: 0,
                endIntensity: 10,
                stepIntensity: 5,
                attemptsPerPoint: 1,
                onProgress: (step, total, result) => reportedSteps.Add((step, total, result.Intensity)));

            Assert.AreEqual(3, series.Count);
            Assert.AreEqual(3, reportedSteps.Count);
            CollectionAssert.AreEqual(new[] { 0.0, 5.0, 10.0 }, series.Select(r => r.Intensity).ToArray());
            CollectionAssert.AreEqual(new[] { (1, 3, 0.0), (2, 3, 5.0), (3, 3, 10.0) }, reportedSteps);

            var fallbackStepSeries = runner.RunSeries(
                _sourceQr,
                ImageDistortionService.DistortionContrast,
                startIntensity: 0,
                endIntensity: 2,
                stepIntensity: 0,
                attemptsPerPoint: 1);
            CollectionAssert.AreEqual(new[] { 0.0, 1.0, 2.0 }, fallbackStepSeries.Select(r => r.Intensity).ToArray());

            using var cts = new CancellationTokenSource();
            var cancelledSeries = runner.RunSeries(
                _sourceQr,
                ImageDistortionService.DistortionContrast,
                startIntensity: 0,
                endIntensity: 20,
                stepIntensity: 5,
                attemptsPerPoint: 1,
                onProgress: (step, _, _) =>
                {
                    if (step == 2)
                        cts.Cancel();
                },
                cancellationToken: cts.Token);
            CollectionAssert.AreEqual(new[] { 0.0, 5.0 }, cancelledSeries.Select(r => r.Intensity).ToArray());
        });
    }

    [TestMethod]
    public void StatisticsService_ToCsv_FormatsInvariantNumbersAndEscapesFields()
    {
        var service = new StatisticsService();
        var results = new[]
        {
            new ExperimentResult("Шум, \"импульсный\"", 12.5, 10, 9, 9, 14.375),
            new ExperimentResult("Поворот", 0, 10, 10, 10, 8.5)
        };

        var lines = service.ToCsv(results)
            .Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);

        Assert.AreEqual(3, lines.Length);
        Assert.AreEqual("Искажение,Интенсивность,Попыток,Успешно_распознано,Валидных_подписей,Вероятность_распознавания,Среднее_время_мс", lines[0]);
        Assert.AreEqual("\"Шум, \"\"импульсный\"\"\",12.5,10,9,9,0.9000,14.38", lines[1]);
        Assert.AreEqual("Поворот,0,10,10,10,1.0000,8.50", lines[2]);
    }

    private static byte[] GetPixels(BitmapSource bitmap)
    {
        var converted = new FormatConvertedBitmap(bitmap, PixelFormats.Bgra32, null, 0);
        int stride = converted.PixelWidth * 4;
        var pixels = new byte[stride * converted.PixelHeight];
        converted.CopyPixels(pixels, stride, 0);
        return pixels;
    }
}
