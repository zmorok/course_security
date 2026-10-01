using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Microsoft.Win32;
using QrAuthenticity.Cryptography;
using QrAuthenticity.Cutted.Models;
using QrAuthenticity.Cutted.Services;
using QrAuthenticity.QR;

namespace QrAuthenticity.Cutted.Tabs;

public partial class QrReadingTab : UserControl
{
    private EncryptedDocumentService? _payloadService;
    private QrCodeService? _qrService;
    private BitmapSource? _loadedQr;
    private bool _isInitialized;

    public Func<BitmapSource?>? GetCurrentGeneratedQr { get; set; }
    public Func<string?>? GetCurrentGeneratedPayload { get; set; }

    public QrReadingTab()
    {
        InitializeComponent();
        DecryptionKeyInput.Text = PayloadEncryptionService.DefaultMasterKey;
        _isInitialized = true;
        ResetDisplay();
    }

    public void Initialize(EncryptedDocumentService payloadService, QrCodeService qrService)
    {
        _payloadService = payloadService;
        _qrService = qrService;
    }

    public void SetImageToRead(BitmapSource image)
    {
        _loadedQr = image;
        VerificationQrImage.Source = image;
        SourceImageRadio.IsChecked = true;
        ResetDisplay();
    }

    public void SetPayloadTextToRead(string payload)
    {
        SourceTextRadio.IsChecked = true;
        InputRawPayloadText.Text = payload;
        ResetDisplay();
    }

    private void VerifySourceRadio_Checked(object sender, RoutedEventArgs e)
    {
        if (!_isInitialized) return;
        bool imageSelected = SourceImageRadio.IsChecked == true;
        ImageSourcePanel.Visibility = imageSelected ? Visibility.Visible : Visibility.Collapsed;
        TextSourcePanel.Visibility = imageSelected ? Visibility.Collapsed : Visibility.Visible;
        ResetDisplay();
    }

    private void InputRawPayloadText_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (_isInitialized) ResetDisplay();
    }

    private void DecryptionKeyInput_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (_isInitialized) ResetDisplay();
    }

    private void ResetDecryptionKey_Click(object sender, RoutedEventArgs e) =>
        DecryptionKeyInput.Text = PayloadEncryptionService.DefaultMasterKey;

    private void ClearPayloadInput_Click(object sender, RoutedEventArgs e)
    {
        InputRawPayloadText.Clear();
        ResetDisplay();
    }

    private void PasteCurrentGeneratedPayload_Click(object sender, RoutedEventArgs e)
    {
        var payload = GetCurrentGeneratedPayload?.Invoke();
        if (string.IsNullOrWhiteSpace(payload))
        {
            ShowNoGeneratedQr();
            return;
        }
        SetPayloadTextToRead(payload);
    }

    private void UseCurrentGeneratedForVerify_Click(object sender, RoutedEventArgs e)
    {
        var image = GetCurrentGeneratedQr?.Invoke();
        if (image is null)
        {
            ShowNoGeneratedQr();
            return;
        }
        SetImageToRead(image);
    }

    private static void ShowNoGeneratedQr() =>
        MessageBox.Show("На вкладке создания QR-код еще не сформирован.", "Информация", MessageBoxButton.OK, MessageBoxImage.Information);

    private void LoadVerificationQr_Click(object sender, RoutedEventArgs e)
    {
        if (_qrService is null) return;
        var dialog = new OpenFileDialog
        {
            Title = "Выберите изображение QR-кода",
            Filter = "Изображения (*.png;*.jpg;*.jpeg;*.bmp)|*.png;*.jpg;*.jpeg;*.bmp"
        };
        if (dialog.ShowDialog() != true) return;

        try
        {
            SetImageToRead(_qrService.Load(dialog.FileName));
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Не удалось загрузить изображение: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void ReadQr_Click(object sender, RoutedEventArgs e) => ReadQr();

    public void ReadQr()
    {
        if (_payloadService is null || _qrService is null) return;
        ClearExtractedFields();

        string? rawPayload;
        if (SourceImageRadio.IsChecked == true)
        {
            if (_loadedQr is null)
            {
                ResetDisplay();
                return;
            }
            rawPayload = _qrService.Decode(_loadedQr);
            if (string.IsNullOrWhiteSpace(rawPayload))
            {
                SetStatus("QR-КОД НЕ РАСПОЗНАН", "Не удалось прочитать QR-код с изображения.", isError: true);
                return;
            }
        }
        else
        {
            rawPayload = InputRawPayloadText.Text.Trim();
            if (string.IsNullOrWhiteSpace(rawPayload))
            {
                ResetDisplay();
                return;
            }
        }

        RawPayloadPreviewText.Text = rawPayload;
        var result = _payloadService.Read(rawPayload, DecryptionKeyInput.Text);
        if (result.Status == QrReadingStatus.Success && result.Data is not null)
        {
            ResultDocNumber.Text = result.Data.DocumentNumber;
            ResultOwner.Text = result.Data.Owner;
            ResultIssued.Text = result.Data.Issued.ToString("dd.MM.yyyy");
            ResultExpires.Text = result.Data.Expires?.ToString("dd.MM.yyyy") ?? "Бессрочный";
            DecodedRawJsonText.Text = result.DecryptedJson;
            SetStatus("ДАННЫЕ РАСШИФРОВАНЫ", result.Message, isSuccess: true);
            return;
        }

        string title = result.Status switch
        {
            QrReadingStatus.DecryptionFailed => "ОШИБКА РАСШИФРОВАНИЯ",
            QrReadingStatus.UnsupportedVersion => "НЕСОВМЕСТИМЫЙ ФОРМАТ ДАННЫХ",
            _ => "НЕВЕРНЫЙ ФОРМАТ ДАННЫХ"
        };
        SetStatus(title, result.Message, isError: true);
    }

    private void ResetDisplay()
    {
        ClearExtractedFields();
        bool hasSource = SourceImageRadio.IsChecked == true
            ? _loadedQr is not null
            : !string.IsNullOrWhiteSpace(InputRawPayloadText.Text);
        SetStatus(hasSource ? "Данные загружены" : "Ожидание проверки",
            hasSource ? "Нажмите «Прочитать QR-код и расшифровать»."
                : "Загрузите изображение QR-кода или вставьте считанный текст.");
    }

    private void ClearExtractedFields()
    {
        ResultDocNumber.Text = "—";
        ResultOwner.Text = "—";
        ResultIssued.Text = "—";
        ResultExpires.Text = "—";
        RawPayloadPreviewText.Clear();
        DecodedRawJsonText.Clear();
    }

    private void SetStatus(string title, string message, bool isError = false, bool isSuccess = false)
    {
        VerificationStatusHeading.Text = title;
        VerificationMessageDetail.Text = message;
        VerificationStatusHeading.Foreground = new SolidColorBrush(
            isError ? Color.FromRgb(207, 34, 46) : isSuccess ? Color.FromRgb(26, 127, 55) : Color.FromRgb(36, 41, 47));
        StatusBadgeBorder.Background = new SolidColorBrush(
            isError ? Color.FromRgb(255, 235, 233) : isSuccess ? Color.FromRgb(223, 247, 228) : Color.FromRgb(246, 248, 250));
        StatusBadgeBorder.BorderBrush = new SolidColorBrush(
            isError ? Color.FromRgb(207, 34, 46) : isSuccess ? Color.FromRgb(45, 164, 78) : Color.FromRgb(208, 215, 222));
    }
}
