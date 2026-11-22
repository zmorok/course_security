using System.IO;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using QrAuthenticity.Cryptography;
using QrAuthenticity.Models;
using QrAuthenticity.QR;
using QrAuthenticity.Serialization;
using QrAuthenticity.Services;
using QrAuthenticity.Verification;
using ZXing.QrCode.Internal;

namespace QrAuthenticity.Tests;

[TestClass]
public sealed class QrRoundtripTests
{
    private static KeyManager _keyManager = null!;
    private static RSA _rsa = null!;
    private static string _publicPem = null!;

    [ClassInitialize]
    public static void ClassSetup(TestContext _)
    {
        _keyManager = new KeyManager();
        _rsa = _keyManager.GenerateRsa(2048);
        _publicPem = _keyManager.ExportPublicPem(_rsa);
    }

    [ClassCleanup]
    public static void ClassCleanup()
    {
        _rsa.Dispose();
    }

    [TestMethod]
    public void QrCodeService_GenerateAndDecode_PlainJson_PreservesPayloadAndVerifies()
    {
        StaTestHelper.Run(() =>
        {
            var creator = new PayloadCreationService();
            var qrService = new QrCodeService();

            var data = new DocumentData("PASSPORT-777", "Сергей Смирнов", new DateOnly(2026, 5, 10), new DateOnly(2036, 5, 10));
            var json = creator.CreateJson(data, _rsa);

            var qrImage = qrService.Generate(json, pixels: 512, level: ErrorCorrectionLevel.Q);
            Assert.IsNotNull(qrImage);
            Assert.IsTrue(qrImage.IsFrozen);

            var decoded = qrService.Decode(qrImage);
            Assert.AreEqual(json, decoded);

            using var store = new TrustedKeyStore();
            store.AddPublicKey(_publicPem);
            var verifier = new AuthenticityVerifier(new PayloadCodec(), new PayloadCanonicalizer(), new SignatureService(), store);

            var verification = verifier.Verify(decoded!, today: new DateOnly(2026, 6, 1));
            Assert.AreEqual(VerificationStatus.Valid, verification.Status);
        });
    }

    [TestMethod]
    public void QrCodeService_EncryptedPayload_PngRoundtripWorksAtAllErrorCorrectionLevels()
    {
        StaTestHelper.Run(() =>
        {
            var encService = new PayloadEncryptionService();
            var creator = new PayloadCreationService(_keyManager, new SignatureService(), new PayloadCanonicalizer(), new PayloadCodec(), encService);
            var qrService = new QrCodeService();

            var data = new DocumentData("DOC-ROUNDTRIP-ENC", "Иван Тестов", new DateOnly(2026, 7, 1), new DateOnly(2029, 7, 1));
            var encryptedPayload = creator.CreateEncryptedPayload(data, _rsa);

            using var store = new TrustedKeyStore();
            store.AddPublicKey(_publicPem);
            var verifier = new AuthenticityVerifier(new PayloadCodec(), new PayloadCanonicalizer(), new SignatureService(), store, encService);

            string pngPath = Path.Combine(Path.GetTempPath(), $"qr_auth_roundtrip_{Guid.NewGuid():N}.png");
            try
            {
                foreach (var level in new[] { ErrorCorrectionLevel.L, ErrorCorrectionLevel.M, ErrorCorrectionLevel.Q, ErrorCorrectionLevel.H })
                {
                    var qrImage = qrService.Generate(encryptedPayload, pixels: 600, level: level);
                    qrService.SavePng(qrImage, pngPath);

                    var reloaded = qrService.Load(pngPath);
                    var decoded = qrService.Decode(reloaded);
                    Assert.AreEqual(encryptedPayload, decoded, $"Раскодирование не совпало на уровне коррекции {level}.");

                    var verification = verifier.Verify(decoded!, today: new DateOnly(2026, 8, 1));
                    Assert.AreEqual(VerificationStatus.Valid, verification.Status);
                    Assert.IsTrue(verification.IsEncrypted);
                    Assert.AreEqual("DOC-ROUNDTRIP-ENC", verification.Payload?.Data.DocumentNumber);
                }
            }
            finally
            {
                if (File.Exists(pngPath))
                {
                    try { File.Delete(pngPath); } catch { }
                }
            }
        });
    }

    [TestMethod]
    public void QrCodeService_Decode_WithoutQuietZone_RecoversPayloadViaPadding()
    {
        StaTestHelper.Run(() =>
        {
            var encService = new PayloadEncryptionService();
            var creator = new PayloadCreationService(_keyManager, new SignatureService(), new PayloadCanonicalizer(), new PayloadCodec(), encService);
            var qrService = new QrCodeService();

            var data = new DocumentData("DOC-CROP-01", "Петр Петров", new DateOnly(2026, 7, 1), new DateOnly(2029, 7, 1));
            var encryptedPayload = creator.CreateEncryptedPayload(data, _rsa);
            var qrImage = qrService.Generate(encryptedPayload, pixels: 600, level: ErrorCorrectionLevel.Q);

            var converted = new FormatConvertedBitmap(qrImage, PixelFormats.Bgra32, null, 0);
            int width = converted.PixelWidth;
            int height = converted.PixelHeight;
            int stride = width * 4;
            var pixels = new byte[stride * height];
            converted.CopyPixels(pixels, stride, 0);

            int minX = width, minY = height, maxX = -1, maxY = -1;
            for (int y = 0; y < height; y++)
            {
                for (int x = 0; x < width; x++)
                {
                    if (pixels[y * stride + x * 4] < 128)
                    {
                        if (x < minX) minX = x;
                        if (y < minY) minY = y;
                        if (x > maxX) maxX = x;
                        if (y > maxY) maxY = y;
                    }
                }
            }

            Assert.IsTrue(maxX > minX && maxY > minY);
            var cropped = new CroppedBitmap(converted, new Int32Rect(minX, minY, maxX - minX + 1, maxY - minY + 1));
            cropped.Freeze();

            var decoded = qrService.Decode(cropped);
            Assert.AreEqual(encryptedPayload, decoded);
        });
    }

    [TestMethod]
    public void QrCodeService_Decode_BlankImage_ReturnsNull()
    {
        StaTestHelper.Run(() =>
        {
            var qrService = new QrCodeService();
            const int size = 200;
            const int stride = size * 4;
            var whitePixels = new byte[stride * size];
            Array.Fill(whitePixels, (byte)255);

            var blank = BitmapSource.Create(size, size, 96, 96, PixelFormats.Bgra32, null, whitePixels, stride);
            blank.Freeze();

            Assert.IsNull(qrService.Decode(blank));
        });
    }
}
