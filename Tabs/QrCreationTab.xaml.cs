using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Imaging;
using Microsoft.Win32;
using QrAuthenticity.Cryptography;
using QrAuthenticity.Models;
using QrAuthenticity.QR;
using QrAuthenticity.Serialization;
using QrAuthenticity.Services;
using ZXing.QrCode.Internal;

namespace QrAuthenticity.Tabs;

public partial class QrCreationTab : UserControl
{
    private PayloadCreationService? _creationService;
    private PayloadCodec? _codec;
    private QrCodeService? _qrService;
    private PayloadEncryptionService? _encryptionService;

    private RSA? _currentPrivateKey;
    private string _currentWorkingKeyId = string.Empty;
    private string _currentWorkingKeyAlias = "Центральный орган сертификации";

    private BitmapSource? _currentGeneratedQr;
    private SignedPayload? _currentSignedPayload;
    private string? _currentPayloadJson;
    private string? _currentQrEncodedPayload;
    private bool _isUpdatingKeyCombo;

    public event Action<SignedPayload, BitmapSource, string>? QrCreated;
    public event Action<string>? KeySelectionChanged;

    public BitmapSource? CurrentGeneratedQr => _currentGeneratedQr;
    public SignedPayload? CurrentSignedPayload => _currentSignedPayload;
    public string? CurrentPayloadJson => _currentPayloadJson;
    public string? CurrentQrEncodedPayload => _currentQrEncodedPayload;
    public RSA? CurrentPrivateKey => _currentPrivateKey;
    public string CurrentWorkingKeyId => _currentWorkingKeyId;
    public string CurrentWorkingKeyAlias => _currentWorkingKeyAlias;

    public QrCreationTab()
    {
        InitializeComponent();
        DocIssuedPicker.SelectedDate = DateTime.Today;
        DocExpiresPicker.SelectedDate = DateTime.Today.AddYears(5);
    }

    public void Initialize(
        PayloadCreationService creationService,
        PayloadCodec codec,
        QrCodeService qrService,
        PayloadEncryptionService? encryptionService = null)
    {
        _creationService = creationService;
        _codec = codec;
        _qrService = qrService;
        _encryptionService = encryptionService ?? new PayloadEncryptionService();
    }

    public void SetWorkingKey(RSA privateKey, string keyId, string alias)
    {
        _currentPrivateKey = privateKey;
        _currentWorkingKeyId = keyId;
        _currentWorkingKeyAlias = alias;

        UpdateAlgorithmDisplay();
    }

    public void UpdateAlgorithmDisplay()
    {
        if (_currentPrivateKey is null)
        {
            CreationAlgorithmDisplay.Text = "—";
            return;
        }

        int keySize = _currentPrivateKey.KeySize;
        CreationAlgorithmDisplay.Text = $"SHA-256 (RSA {keySize} бит)";
    }

    public void RefreshKeyOptions(IEnumerable<SigningKeyOption> options, string? selectedKeyId)
    {
        _isUpdatingKeyCombo = true;
        try
        {
            var list = options.ToList();
            CreationKeySelectCombo.ItemsSource = list;

            string targetId = selectedKeyId ?? _currentWorkingKeyId;
            var selected = list.FirstOrDefault(k => string.Equals(k.KeyId, targetId, StringComparison.OrdinalIgnoreCase))
                           ?? list.LastOrDefault();

            if (selected is not null)
            {
                CreationKeySelectCombo.SelectedItem = selected;
            }
        }
        finally
        {
            _isUpdatingKeyCombo = false;
        }
    }

    private void CreationKeySelectCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_isUpdatingKeyCombo) return;

        if (CreationKeySelectCombo.SelectedItem is SigningKeyOption selected)
        {
            KeySelectionChanged?.Invoke(selected.KeyId);
        }
    }

    private void EncryptPayloadCheckBox_Changed(object sender, RoutedEventArgs e)
    {
        if (EncryptionKeyPanel is not null)
        {
            EncryptionKeyPanel.Visibility = EncryptPayloadCheckBox.IsChecked == true
                ? Visibility.Visible
                : Visibility.Collapsed;
        }
    }

    private void ResetCreationEncryptionKey_Click(object sender, RoutedEventArgs e)
    {
        CreationEncryptionKeyInput.Text = PayloadEncryptionService.DefaultMasterKey;
    }

    private void CopyEncryptedPayload_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(_currentQrEncodedPayload))
        {
            MessageBox.Show("Сначала сформируйте QR-код.", "Внимание", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        Clipboard.SetText(_currentQrEncodedPayload);
        MessageBox.Show("Зашифрованная строка QR-кода скопирована в буфер обмена!\nТеперь её можно вставить на вкладке «Верификация» для проверки.", "Скопировано", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void CreateSignedQr_Click(object sender, RoutedEventArgs e)
    {
        CreateSignedQr();
    }

    public void CreateSignedQr()
    {
        if (_creationService is null || _codec is null || _qrService is null) return;
        _encryptionService ??= new PayloadEncryptionService();

        try
        {
            if (_currentPrivateKey is null)
            {
                MessageBox.Show("Ключ для подписи еще не выбран или не создан.", "Внимание", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var docNumber = DocNumberInput.Text.Trim();
            var owner = DocOwnerInput.Text.Trim();
            var issued = DocIssuedPicker.SelectedDate.HasValue
                ? DateOnly.FromDateTime(DocIssuedPicker.SelectedDate.Value)
                : DateOnly.FromDateTime(DateTime.Today);
            DateOnly? expires = DocExpiresPicker.SelectedDate.HasValue
                ? DateOnly.FromDateTime(DocExpiresPicker.SelectedDate.Value)
                : null;

            var documentData = new DocumentData(docNumber, owner, issued, expires);
            _currentSignedPayload = _creationService.Create(documentData, _currentPrivateKey);
            _currentPayloadJson = _codec.Encode(_currentSignedPayload);

            CreationJsonPreview.Text = _currentPayloadJson;
            UpdateAlgorithmDisplay();

            bool isEncrypt = EncryptPayloadCheckBox.IsChecked == true;
            if (isEncrypt)
            {
                string encKey = CreationEncryptionKeyInput.Text.Trim();
                _currentQrEncodedPayload = _encryptionService.Encrypt(_currentPayloadJson, encKey);
                CreationEncryptedPreview.Text = _currentQrEncodedPayload;
                CreationEncryptedExpander.Header = $"Зашифрованный QR-payload ({_currentQrEncodedPayload.Length} симв., виден телефону)";
            }
            else
            {
                _currentQrEncodedPayload = _currentPayloadJson;
                CreationEncryptedPreview.Text = "(Шифрование отключено. В QR-код помещен открытый JSON)";
                CreationEncryptedExpander.Header = "Зашифрованная строка QR (шифрование выключено)";
            }

            var ecLevel = GetSelectedErrorCorrectionLevel();
            _currentGeneratedQr = _qrService.Generate(_currentQrEncodedPayload, pixels: 600, level: ecLevel);
            GeneratedQrImage.Source = _currentGeneratedQr;

            int payloadBytes = Encoding.UTF8.GetByteCount(_currentQrEncodedPayload);
            string encLabel = isEncrypt ? "Зашифровано Feistel-128-CBC" : "Открытый JSON";
            QrMetricsLabel.Text = $"Размер данных: {payloadBytes} байт ({encLabel}) | Коррекция Рида-Соломона: {ecLevel} | Разрешение: {_currentGeneratedQr.PixelWidth}x{_currentGeneratedQr.PixelHeight}";

            QrCreated?.Invoke(_currentSignedPayload, _currentGeneratedQr, _currentQrEncodedPayload);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Ошибка формирования QR-кода: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private ErrorCorrectionLevel GetSelectedErrorCorrectionLevel()
    {
        return ErrorCorrectionCombo.SelectedIndex switch
        {
            0 => ErrorCorrectionLevel.L,
            1 => ErrorCorrectionLevel.M,
            2 => ErrorCorrectionLevel.Q,
            3 => ErrorCorrectionLevel.H,
            _ => ErrorCorrectionLevel.Q
        };
    }

    private void SaveQrImage_Click(object sender, RoutedEventArgs e)
    {
        if (_currentGeneratedQr is null)
        {
            MessageBox.Show("Сначала сформируйте QR-код.", "Внимание", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var dialog = new SaveFileDialog
        {
            Title = "Сохранение подписанного QR-кода",
            Filter = "Изображение PNG (*.png)|*.png",
            FileName = "signed_qr_document.png"
        };

        if (dialog.ShowDialog() == true)
        {
            try
            {
                _qrService?.SavePng(_currentGeneratedQr, dialog.FileName);
                MessageBox.Show($"QR-код успешно сохранен:\n{dialog.FileName}", "Файл сохранен", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Не удалось сохранить файл: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
}
