using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Imaging;
using Microsoft.Win32;
using QrAuthenticity.Cryptography;
using QrAuthenticity.Cutted.Services;
using QrAuthenticity.Models;
using QrAuthenticity.QR;
using ZXing.QrCode.Internal;

namespace QrAuthenticity.Cutted.Tabs;

public partial class QrCreationTab : UserControl
{
    private EncryptedDocumentService? _payloadService;
    private QrCodeService? _qrService;

    public BitmapSource? CurrentGeneratedQr { get; private set; }
    public string? CurrentQrEncodedPayload { get; private set; }

    public QrCreationTab()
    {
        InitializeComponent();
        DocIssuedPicker.SelectedDate = DateTime.Today;
        DocExpiresPicker.SelectedDate = DateTime.Today.AddYears(5);
        CreationEncryptionKeyInput.Text = PayloadEncryptionService.DefaultMasterKey;
    }

    public void Initialize(EncryptedDocumentService payloadService, QrCodeService qrService)
    {
        _payloadService = payloadService;
        _qrService = qrService;
    }

    private void ResetCreationEncryptionKey_Click(object sender, RoutedEventArgs e) =>
        CreationEncryptionKeyInput.Text = PayloadEncryptionService.DefaultMasterKey;

    private void CreateQr_Click(object sender, RoutedEventArgs e) => CreateQr();

    public void CreateQr()
    {
        if (_payloadService is null || _qrService is null) return;

        try
        {
            var data = new DocumentData(
                DocNumberInput.Text.Trim(),
                DocOwnerInput.Text.Trim(),
                DateOnly.FromDateTime(DocIssuedPicker.SelectedDate ?? DateTime.Today),
                DocExpiresPicker.SelectedDate is DateTime expires ? DateOnly.FromDateTime(expires) : null);

            string key = CreationEncryptionKeyInput.Text.Trim();
            string encrypted = _payloadService.Create(data, key);
            var reading = _payloadService.Read(encrypted, key);
            var level = ErrorCorrectionCombo.SelectedIndex switch
            {
                0 => ErrorCorrectionLevel.L,
                1 => ErrorCorrectionLevel.M,
                3 => ErrorCorrectionLevel.H,
                _ => ErrorCorrectionLevel.Q
            };
            var image = _qrService.Generate(encrypted, pixels: 600, level: level);

            CurrentGeneratedQr = image;
            CurrentQrEncodedPayload = encrypted;
            GeneratedQrImage.Source = image;
            CreationEncryptedPreview.Text = encrypted;
            CreationJsonPreview.Text = reading.DecryptedJson;
            int bytes = Encoding.UTF8.GetByteCount(encrypted);
            QrMetricsLabel.Text = $"Размер данных: {bytes} байт | Коррекция Рида-Соломона: {level} | Разрешение: {image.PixelWidth}×{image.PixelHeight}";
            QrMetricsLabel.ToolTip = "Шифрование Feistel-128-CBC";
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Ошибка формирования QR-кода: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void SaveQrImage_Click(object sender, RoutedEventArgs e)
    {
        if (_qrService is null || CurrentGeneratedQr is null)
        {
            MessageBox.Show("Сначала сформируйте QR-код.", "Информация", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var dialog = new SaveFileDialog
        {
            Title = "Сохранение QR-кода",
            Filter = "Изображение PNG (*.png)|*.png",
            FileName = "qr_document.png"
        };
        if (dialog.ShowDialog() != true) return;

        try
        {
            _qrService.SavePng(CurrentGeneratedQr, dialog.FileName);
            MessageBox.Show($"QR-код сохранен:\n{dialog.FileName}", "Файл сохранен", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Не удалось сохранить изображение: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}
