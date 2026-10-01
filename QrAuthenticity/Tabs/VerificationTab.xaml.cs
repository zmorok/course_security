using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Microsoft.Win32;
using QrAuthenticity.Cryptography;
using QrAuthenticity.Models;
using QrAuthenticity.QR;
using QrAuthenticity.Verification;

namespace QrAuthenticity.Tabs;

public partial class VerificationTab : UserControl
{
    private QrCodeService? _qrService;
    private AuthenticityVerifier? _verifier;
    private TrustedKeyStore? _trustedKeys;

    private BitmapSource? _loadedVerificationQr;

    public Func<BitmapSource?>? GetCurrentGeneratedQr { get; set; }
    public Func<string?>? GetCurrentGeneratedPayload { get; set; }

    public VerificationTab()
    {
        InitializeComponent();
    }

    public void Initialize(
        QrCodeService qrService,
        AuthenticityVerifier verifier,
        TrustedKeyStore trustedKeys)
    {
        _qrService = qrService;
        _verifier = verifier;
        _trustedKeys = trustedKeys;
    }

    public void SetImageToVerify(BitmapSource source)
    {
        _loadedVerificationQr = source;
        VerificationQrImage.Source = _loadedVerificationQr;
        ResetVerificationDisplay();
    }

    public void SetPayloadTextToVerify(string payload)
    {
        SourceTextRadio.IsChecked = true;
        InputRawPayloadText.Text = payload;
        ResetVerificationDisplay();
    }

    public void ResetToWaitingState()
    {
        VerificationStatusHeading.Text = "Ожидание проверки";
        VerificationStatusHeading.Foreground = new SolidColorBrush(Color.FromRgb(36, 41, 47));
        StatusBadgeBorder.Background = new SolidColorBrush(Color.FromRgb(246, 248, 250));
        StatusBadgeBorder.BorderBrush = new SolidColorBrush(Color.FromRgb(208, 215, 222));
        VerificationMessageDetail.Text = "Загрузите изображение QR-кода или вставьте считанный текст и нажмите кнопку проверки.";

        ClearExtractedFields();
    }

    public void ResetVerificationDisplay()
    {
        VerificationStatusHeading.Text = "Данные загружены";
        VerificationStatusHeading.Foreground = new SolidColorBrush(Color.FromRgb(36, 41, 47));
        StatusBadgeBorder.Background = new SolidColorBrush(Color.FromRgb(246, 248, 250));
        StatusBadgeBorder.BorderBrush = new SolidColorBrush(Color.FromRgb(208, 215, 222));
        VerificationMessageDetail.Text = "Нажмите «Проверить цифровую подпись и расшифровать» для запуска анализа.";

        ClearExtractedFields();
    }

    private void ClearExtractedFields()
    {
        ResultDocNumber.Text = "—";
        ResultOwner.Text = "—";
        ResultIssued.Text = "—";
        ResultExpires.Text = "—";
        ResultKeyId.Text = "—";
        ResultKeyTrustStatus.Text = "—";
        ResultKeyTrustStatus.Foreground = new SolidColorBrush(Color.FromRgb(87, 96, 106));
        ResultAlgorithm.Text = "—";
        RawPayloadPreviewText.Text = string.Empty;
        DecodedRawJsonText.Text = string.Empty;
    }

    private void VerifySourceRadio_Checked(object sender, RoutedEventArgs e)
    {
        if (ImageSourcePanel is null || TextSourcePanel is null) return;

        if (SourceImageRadio.IsChecked == true)
        {
            ImageSourcePanel.Visibility = Visibility.Visible;
            TextSourcePanel.Visibility = Visibility.Collapsed;
            if (_loadedVerificationQr is not null)
            {
                ResetVerificationDisplay();
            }
            else
            {
                ResetToWaitingState();
            }
        }
        else
        {
            ImageSourcePanel.Visibility = Visibility.Collapsed;
            TextSourcePanel.Visibility = Visibility.Visible;
            if (!string.IsNullOrWhiteSpace(InputRawPayloadText?.Text))
            {
                ResetVerificationDisplay();
            }
            else
            {
                ResetToWaitingState();
            }
        }
    }

    private void InputRawPayloadText_TextChanged(object sender, TextChangedEventArgs e)
    {
        var text = InputRawPayloadText.Text.Trim();
        if (string.IsNullOrEmpty(text))
        {
            ResetToWaitingState();
        }
        else
        {
            ResetVerificationDisplay();
        }
    }

    private void PasteCurrentGeneratedPayload_Click(object sender, RoutedEventArgs e)
    {
        var current = GetCurrentGeneratedPayload?.Invoke();
        if (string.IsNullOrWhiteSpace(current))
        {
            MessageBox.Show("На вкладке создания QR-код еще не сгенерирован.", "Информация", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        InputRawPayloadText.Text = current;
    }

    private void ClearPayloadInput_Click(object sender, RoutedEventArgs e)
    {
        InputRawPayloadText.Text = string.Empty;
        ResetToWaitingState();
    }

    private void ResetDecryptionKey_Click(object sender, RoutedEventArgs e)
    {
        DecryptionKeyInput.Text = PayloadEncryptionService.DefaultMasterKey;
    }

    private void LoadVerificationQr_Click(object sender, RoutedEventArgs e)
    {
        if (_qrService is null) return;

        if (_loadedVerificationQr is not null)
        {
            var confirmResult = MessageBox.Show(
                "В области проверки уже загружен QR-код. Заменить его новым изображением из файла?",
                "Подтверждение замены",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (confirmResult != MessageBoxResult.Yes)
            {
                return;
            }
        }

        var dialog = new OpenFileDialog
        {
            Title = "Выберите изображение QR-кода для проверки",
            Filter = "Изображения (*.png;*.jpg;*.jpeg;*.bmp)|*.png;*.jpg;*.jpeg;*.bmp"
        };

        if (dialog.ShowDialog() == true)
        {
            try
            {
                var bmp = _qrService.Load(dialog.FileName);
                SetImageToVerify(bmp);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Не удалось загрузить изображение: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    private void UseCurrentGeneratedForVerify_Click(object sender, RoutedEventArgs e)
    {
        var current = GetCurrentGeneratedQr?.Invoke();
        if (current is null)
        {
            MessageBox.Show("QR-код на вкладке создания еще не сформирован.", "Внимание", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (_loadedVerificationQr is not null)
        {
            var confirmResult = MessageBox.Show(
                "В области проверки уже загружен QR-код. Заменить его текущим сгенерированным QR-кодом?",
                "Подтверждение замены",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (confirmResult != MessageBoxResult.Yes)
            {
                return;
            }
        }

        SetImageToVerify(current);
    }

    private void RunVerification_Click(object sender, RoutedEventArgs e)
    {
        if (_verifier is null || _trustedKeys is null) return;

        string payloadToVerify;

        if (SourceImageRadio.IsChecked == true)
        {
            if (_qrService is null) return;

            if (_loadedVerificationQr is null)
            {
                MessageBox.Show("Загрузите изображение QR-кода или воспользуйтесь кнопкой «Взять сгенерированный».", "Внимание", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var decoded = _qrService.Decode(_loadedVerificationQr);
            if (decoded is null)
            {
                SetStatusBadge(
                    "QR-КОД НЕ РАСПОЗНАН",
                    "Декодер не смог прочитать матрицу QR-кода. Возможно, изображение повреждено или сильно размыто.",
                    Color.FromRgb(246, 248, 250),
                    Color.FromRgb(87, 96, 106),
                    Color.FromRgb(208, 215, 222)
                );
                return;
            }

            payloadToVerify = decoded;
        }
        else
        {
            payloadToVerify = InputRawPayloadText.Text.Trim();
            if (string.IsNullOrWhiteSpace(payloadToVerify))
            {
                MessageBox.Show("Введите или вставьте в текстовое поле полезную нагрузку QR-кода (например, строку, отсканированную камерой смартфона).", "Внимание", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
        }

        RawPayloadPreviewText.Text = payloadToVerify;

        string decKey = DecryptionKeyInput.Text.Trim();
        var result = _verifier.Verify(payloadToVerify, decKey);

        DecodedRawJsonText.Text = result.DecryptedJson ?? (result.IsEncrypted ? "(Не удалось расшифровать JSON)" : payloadToVerify);

        if (result.Payload is not null)
        {
            ResultDocNumber.Text = result.Payload.Data.DocumentNumber;
            ResultOwner.Text = result.Payload.Data.Owner;
            ResultIssued.Text = result.Payload.Data.Issued.ToString("dd.MM.yyyy");
            ResultExpires.Text = result.Payload.Data.Expires?.ToString("dd.MM.yyyy") ?? "Бессрочный";
            ResultKeyId.Text = result.Payload.KeyId;

            bool isTrusted = _trustedKeys.TryGet(result.Payload.KeyId, out var pubKey);
            ResultKeyTrustStatus.Text = isTrusted ? "Ключ в списке доверенных" : "Неизвестный ключ (не доверен)";
            ResultKeyTrustStatus.Foreground = isTrusted
                ? new SolidColorBrush(Color.FromRgb(26, 127, 55))
                : new SolidColorBrush(Color.FromRgb(207, 34, 46));

            if (pubKey is not null)
            {
                ResultAlgorithm.Text = $"SHA-256 (RSA {pubKey.KeySize} бит)";
            }
            else
            {
                ResultAlgorithm.Text = result.Payload.Algorithm;
            }
        }

        switch (result.Status)
        {
            case VerificationStatus.Valid:
                SetStatusBadge(
                    "ПОДЛИННОСТЬ ПОДТВЕРЖДЕНА",
                    result.Message,
                    Color.FromRgb(223, 247, 228),
                    Color.FromRgb(26, 127, 55),
                    Color.FromRgb(45, 164, 78)
                );
                break;

            case VerificationStatus.DecryptionFailed:
                SetStatusBadge(
                    "ОШИБКА РАСШИФРОВАНИЯ",
                    result.Message,
                    Color.FromRgb(255, 235, 233),
                    Color.FromRgb(207, 34, 46),
                    Color.FromRgb(207, 34, 46)
                );
                break;

            case VerificationStatus.InvalidSignature:
                SetStatusBadge(
                    "ПОДПИСЬ НЕВЕРНА (ДАННЫЕ ИЗМЕНЕНЫ)",
                    result.Message,
                    Color.FromRgb(255, 235, 233),
                    Color.FromRgb(207, 34, 46),
                    Color.FromRgb(207, 34, 46)
                );
                break;

            case VerificationStatus.UnknownKey:
                SetStatusBadge(
                    "КЛЮЧ ИЗДАТЕЛЯ НЕ ДОВЕРЕН",
                    result.Message,
                    Color.FromRgb(255, 248, 197),
                    Color.FromRgb(154, 103, 0),
                    Color.FromRgb(212, 167, 44)
                );
                break;

            case VerificationStatus.Expired:
                SetStatusBadge(
                    "СРОК ДЕЙСТВИЯ ИСТЕК",
                    result.Message,
                    Color.FromRgb(255, 232, 214),
                    Color.FromRgb(188, 76, 0),
                    Color.FromRgb(217, 108, 0)
                );
                break;

            case VerificationStatus.InvalidPayload:
                SetStatusBadge(
                    "НЕВЕРНЫЙ ФОРМАТ КОНТЕЙНЕРА",
                    result.Message,
                    Color.FromRgb(255, 235, 233),
                    Color.FromRgb(207, 34, 46),
                    Color.FromRgb(207, 34, 46)
                );
                break;

            case VerificationStatus.UnsupportedVersion:
            case VerificationStatus.UnsupportedAlgorithm:
                SetStatusBadge(
                    "НЕСОВМЕСТИМЫЙ ПРОТОКОЛ",
                    result.Message,
                    Color.FromRgb(255, 248, 197),
                    Color.FromRgb(154, 103, 0),
                    Color.FromRgb(212, 167, 44)
                );
                break;

            default:
                SetStatusBadge(
                    "ОШИБКА ПРОВЕРКИ",
                    result.Message,
                    Color.FromRgb(246, 248, 250),
                    Color.FromRgb(87, 96, 106),
                    Color.FromRgb(208, 215, 222)
                );
                break;
        }
    }

    private void SetStatusBadge(string title, string message, Color bg, Color fg, Color border)
    {
        VerificationStatusHeading.Text = title;
        VerificationStatusHeading.Foreground = new SolidColorBrush(fg);
        VerificationMessageDetail.Text = message;
        StatusBadgeBorder.Background = new SolidColorBrush(bg);
        StatusBadgeBorder.BorderBrush = new SolidColorBrush(border);
    }
}
