using System.IO;
using System.Runtime.ExceptionServices;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using QrAuthenticity.Cryptography;
using QrAuthenticity.Cutted.Models;
using QrAuthenticity.Cutted.Services;
using QrAuthenticity.Cutted.Tabs;
using QrAuthenticity.Models;
using QrAuthenticity.QR;
using ZXing.QrCode.Internal;

namespace QrAuthenticity.Cutted.Tests;

[TestClass]
public sealed class EncryptedDocumentTests
{
    private static readonly DocumentData Sample = new("DOC-123", "Иван Иванов",
        new DateOnly(2026, 10, 1), new DateOnly(2031, 10, 1));

    [DataTestMethod]
    [DataRow(null)]
    [DataRow("Мой собственный ключ 123")]
    public void EncryptedRoundtripPreservesDocumentAndContainsOnlyVersionAndData(string? key)
    {
        var service = new EncryptedDocumentService();
        string encrypted = service.Create(Sample, key);
        var result = service.Read(encrypted, key);
        Assert.IsTrue(encrypted.StartsWith("ENC1."));
        Assert.IsFalse(encrypted.Contains(Sample.Owner));
        Assert.AreEqual(QrReadingStatus.Success, result.Status);
        Assert.AreEqual(Sample, result.Data);
        using var json = JsonDocument.Parse(result.DecryptedJson!);
        CollectionAssert.AreEquivalent(new[] { "v", "data" },
            json.RootElement.EnumerateObject().Select(p => p.Name).ToArray());
        Assert.AreEqual(2, json.RootElement.GetProperty("v").GetInt32());
    }

    [TestMethod]
    public void DocumentWithoutExpiryCanBeRead()
    {
        var service = new EncryptedDocumentService();
        var data = Sample with { Expires = null };
        Assert.AreEqual(data, service.Read(service.Create(data)).Data);
    }

    [TestMethod]
    public void WrongKeyDoesNotReportSuccessOrExposeDocument()
    {
        var service = new EncryptedDocumentService();
        var result = service.Read(service.Create(Sample, "correct-key"), "wrong-key");
        Assert.AreNotEqual(QrReadingStatus.Success, result.Status);
        Assert.IsNull(result.Data);
        Assert.IsNull(result.DecryptedJson);
    }

    [DataTestMethod]
    [DataRow(null)]
    [DataRow("")]
    [DataRow("{}")] // Открытый JSON не является зашифрованным QR.
    [DataRow("ENC1.")]
    [DataRow("ENC1.!")]
    [DataRow("ENC1.AA")]
    public void InvalidInputReturnsFailureWithoutThrowing(string? input)
    {
        var result = new EncryptedDocumentService().Read(input);
        Assert.AreNotEqual(QrReadingStatus.Success, result.Status);
        Assert.IsNull(result.Data);
    }

    [DataTestMethod]
    [DataRow("{\"v\":2,\"data\":null}")]
    [DataRow("{\"v\":2,\"data\":{}}")]
    [DataRow("{\"data\":{\"document\":\"DOC\",\"owner\":\"Иван\",\"issued\":\"01.10.2026\",\"expires\":null}}")]
    [DataRow("{\"v\":2,\"data\":{\"document\":\"DOC\",\"owner\":\"Иван\",\"issued\":\"01.10.2026\"}}")]
    [DataRow("{\"v\":2,\"data\":{\"document\":\"\",\"owner\":\"Иван\",\"issued\":\"01.10.2026\",\"expires\":null}}")]
    [DataRow("{\"v\":1,\"alg\":\"PS256\",\"kid\":\"key\",\"signature\":\"fake\",\"data\":{\"document\":\"DOC\",\"owner\":\"Иван\",\"issued\":\"01.10.2026\",\"expires\":null}}")]
    public void InvalidOrSignedContainerIsRejected(string json)
    {
        string encrypted = new PayloadEncryptionService().Encrypt(json);
        Assert.AreEqual(QrReadingStatus.InvalidPayload, new EncryptedDocumentService().Read(encrypted).Status);
    }

    [TestMethod]
    public void UnsupportedVersionIsRejected()
    {
        var encryption = new PayloadEncryptionService();
        var service = new EncryptedDocumentService();
        string json = encryption.Decrypt(service.Create(Sample)).Replace("\"v\":2", "\"v\":99");
        Assert.AreEqual(QrReadingStatus.UnsupportedVersion, service.Read(encryption.Encrypt(json)).Status);
    }

    [TestMethod]
    public void InvalidDocumentCannotBeCreated()
    {
        var service = new EncryptedDocumentService();
        Assert.ThrowsException<ArgumentException>(() => service.Create(Sample with { Owner = " " }));
        Assert.ThrowsException<ArgumentException>(() => service.Create(Sample with { Expires = Sample.Issued.AddDays(-1) }));
    }

    [TestMethod]
    public void CuttedAssemblyContainsNoFullApplicationServices()
    {
        var types = typeof(EncryptedDocumentService).Assembly.GetTypes().Select(t => t.Name).ToArray();
        foreach (string forbidden in new[] { "SignatureService", "KeyManager", "TrustedKeyStore", "SignedPayload",
            "AuthenticityVerifier", "PayloadCanonicalizer", "AttackLabTab", "KeyManagementTab", "ExperimentsTab", "ExperimentRunner" })
            CollectionAssert.DoesNotContain(types, forbidden);
        Assert.IsFalse(typeof(EncryptedDocumentService).Assembly.GetReferencedAssemblies().Any(a => a.Name == "QrAuthenticity"));
    }

    [TestMethod]
    public void PngRoundtripWorksAtEveryErrorCorrectionLevel()
    {
        OnStaThread(() =>
        {
            var service = new EncryptedDocumentService();
            var qr = new QrCodeService();
            string encrypted = service.Create(Sample, "custom-qr-key");
            string path = Path.Combine(Path.GetTempPath(), $"cutted-qr-{Guid.NewGuid():N}.png");
            try
            {
                foreach (var level in new[] { ErrorCorrectionLevel.L, ErrorCorrectionLevel.M, ErrorCorrectionLevel.Q, ErrorCorrectionLevel.H })
                {
                    qr.SavePng(qr.Generate(encrypted, 600, level), path);
                    string? decoded = qr.Decode(qr.Load(path));
                    Assert.AreEqual(encrypted, decoded);
                    Assert.AreEqual(Sample, service.Read(decoded, "custom-qr-key").Data);
                }
            }
            finally { File.Delete(path); }
        });
    }

    [TestMethod]
    public void WindowStartsWithTwoTabsAndClearsResultsAfterKeyOrSourceChanges()
    {
        OnStaThread(() =>
        {
            var app = new App();
            app.InitializeComponent();
            var window = new MainWindow();
            try
            {
                var content = (FrameworkElement)window.Content;
                content.Measure(new Size(1176, 780));
                content.Arrange(new Rect(0, 0, 1176, 780));
                content.UpdateLayout();
                var tabs = ((Grid)content).Children.OfType<TabControl>().Single();
                Assert.AreEqual(2, tabs.Items.Count);
                Assert.AreEqual("2. Проверка QR-кода", ((TabItem)tabs.Items[1]).Header);
                var creation = (QrCreationTab)window.FindName("CreationTab");
                var reading = (QrReadingTab)window.FindName("ReadingTab");
                Assert.IsNotNull(creation.CurrentGeneratedQr);
                Assert.IsNotNull(creation.CurrentQrEncodedPayload);

                reading.SetImageToRead(creation.CurrentGeneratedQr!);
                reading.ReadQr();
                Assert.AreEqual("ДАННЫЕ РАСШИФРОВАНЫ", ((TextBlock)reading.FindName("VerificationStatusHeading")).Text);
                var keyInput = (TextBox)reading.FindName("DecryptionKeyInput");
                keyInput.Text = "wrong-key";
                Assert.AreEqual("—", ((TextBlock)reading.FindName("ResultOwner")).Text);
                reading.ReadQr();
                Assert.AreNotEqual("ДАННЫЕ РАСШИФРОВАНЫ", ((TextBlock)reading.FindName("VerificationStatusHeading")).Text);

                ((TextBox)creation.FindName("CreationEncryptionKeyInput")).Text = "custom-ui-key";
                creation.CreateQr();
                keyInput.Text = "custom-ui-key";
                reading.SetPayloadTextToRead(creation.CurrentQrEncodedPayload!);
                reading.ReadQr();
                Assert.AreEqual("Иванов Иван Иванович", ((TextBlock)reading.FindName("ResultOwner")).Text);
                reading.SetPayloadTextToRead("ENC1.!");
                reading.ReadQr();
                Assert.AreEqual("—", ((TextBlock)reading.FindName("ResultOwner")).Text);
                Assert.AreEqual("", ((TextBox)reading.FindName("DecodedRawJsonText")).Text);

                // Optional offscreen previews for manual layout inspection during development.
                string? previewDirectory = Environment.GetEnvironmentVariable("CUTTED_PREVIEW_DIRECTORY");
                if (!string.IsNullOrEmpty(previewDirectory))
                {
                    Directory.CreateDirectory(previewDirectory);
                    SavePreview(content, Path.Combine(previewDirectory, "creation.png"));
                    tabs.SelectedIndex = 1;
                    reading.SetImageToRead(creation.CurrentGeneratedQr!);
                    reading.ReadQr();
                    content.UpdateLayout();
                    SavePreview(content, Path.Combine(previewDirectory, "reading.png"));
                }
            }
            finally { window.Close(); app.Shutdown(); }
        });
    }

    private static void SavePreview(FrameworkElement content, string path)
    {
        var bitmap = new RenderTargetBitmap((int)content.ActualWidth, (int)content.ActualHeight, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(content);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using var stream = File.Create(path);
        encoder.Save(stream);
    }

    private static void OnStaThread(Action action)
    {
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try { action(); }
            catch (Exception ex) { failure = ex; }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        if (!thread.Join(TimeSpan.FromSeconds(30))) Assert.Fail("STA operation timed out.");
        if (failure is not null) ExceptionDispatchInfo.Capture(failure).Throw();
    }
}
