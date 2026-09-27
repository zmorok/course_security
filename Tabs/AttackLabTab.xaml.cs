using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Imaging;
using Microsoft.Win32;
using QrAuthenticity.Cryptography;
using QrAuthenticity.Models;
using QrAuthenticity.QR;
using QrAuthenticity.Serialization;
using QrAuthenticity.Services;
using QrAuthenticity.Verification;
using ZXing.QrCode.Internal;

namespace QrAuthenticity.Tabs;

public partial class AttackLabTab : UserControl
{
    private KeyManager? _keyManager;
    private PayloadCreationService? _creationService;
    private PayloadCodec? _codec;
    private QrCodeService? _qrService;
    private AuthenticityVerifier? _verifier;
    private PayloadEncryptionService? _encryptionService;

    private BitmapSource? _tamperedQr;
    private SignedPayload? _originalPayloadForTamper;
    private RSA? _attackerPrivateKey;

    public Func<(SignedPayload? Payload, BitmapSource? Image)>? RequestCurrentPayload { get; set; }

    public AttackLabTab()
    {
        InitializeComponent();
    }

    public void Initialize(
        KeyManager keyManager,
        PayloadCreationService creationService,
        PayloadCodec codec,
        QrCodeService qrService,
        AuthenticityVerifier verifier,
        PayloadEncryptionService? encryptionService = null)
    {
        _keyManager = keyManager;
        _creationService = creationService;
        _codec = codec;
        _qrService = qrService;
        _verifier = verifier;
        _encryptionService = encryptionService ?? new PayloadEncryptionService();
    }

    public void LoadCurrentDocument(SignedPayload? payload, BitmapSource? image)
    {
        if (payload is null) return;

        _originalPayloadForTamper = payload;
        TamperDocNumber.Text = payload.Data.DocumentNumber;
        TamperOwner.Text = payload.Data.Owner;
        TamperIssuedPicker.SelectedDate = payload.Data.Issued.ToDateTime(TimeOnly.MinValue);
        TamperExpiresPicker.SelectedDate = payload.Data.Expires?.ToDateTime(TimeOnly.MinValue);

        if (image is not null)
        {
            _tamperedQr = image;
            TamperedQrPreview.Source = _tamperedQr;
        }
    }

    private void TamperLoadCurrent_Click(object sender, RoutedEventArgs e)
    {
        var current = RequestCurrentPayload?.Invoke();
        if (current.HasValue && current.Value.Payload is not null)
        {
            LoadCurrentDocument(current.Value.Payload, current.Value.Image);
        }
    }

    private void TamperLoadImage_Click(object sender, RoutedEventArgs e)
    {
        if (_qrService is null || _codec is null) return;

        var dialog = new OpenFileDialog
        {
            Title = "Выберите QR-код для демонстрации атак",
            Filter = "Изображения (*.png;*.jpg;*.jpeg;*.bmp)|*.png;*.jpg;*.jpeg;*.bmp"
        };

        if (dialog.ShowDialog() == true)
        {
            try
            {
                var bmp = _qrService.Load(dialog.FileName);
                var text = _qrService.Decode(bmp);
                if (text is null)
                {
                    MessageBox.Show("QR-код на изображении не найден.", "Внимание", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                _encryptionService ??= new PayloadEncryptionService();
                string json = _encryptionService.Decrypt(text);
                _originalPayloadForTamper = _codec.Decode(json);
                TamperDocNumber.Text = _originalPayloadForTamper.Data.DocumentNumber;
                TamperOwner.Text = _originalPayloadForTamper.Data.Owner;
                TamperIssuedPicker.SelectedDate = _originalPayloadForTamper.Data.Issued.ToDateTime(TimeOnly.MinValue);
                TamperExpiresPicker.SelectedDate = _originalPayloadForTamper.Data.Expires?.ToDateTime(TimeOnly.MinValue);

                _tamperedQr = bmp;
                TamperedQrPreview.Source = _tamperedQr;

                MessageBox.Show("Реквизиты из QR-кода успешно загружены для демонстрации.", "Успех", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка разбора контейнера: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    private void TamperReset_Click(object sender, RoutedEventArgs e)
    {
        if (_originalPayloadForTamper is not null)
        {
            TamperDocNumber.Text = _originalPayloadForTamper.Data.DocumentNumber;
            TamperOwner.Text = _originalPayloadForTamper.Data.Owner;
            TamperIssuedPicker.SelectedDate = _originalPayloadForTamper.Data.Issued.ToDateTime(TimeOnly.MinValue);
            TamperExpiresPicker.SelectedDate = _originalPayloadForTamper.Data.Expires?.ToDateTime(TimeOnly.MinValue);
        }
        else
        {
            TamperLoadCurrent_Click(sender, e);
        }
    }

    private void TamperAttackOldSig_Click(object sender, RoutedEventArgs e)
    {
        if (_codec is null || _qrService is null) return;

        if (_originalPayloadForTamper is null)
        {
            TamperLoadCurrent_Click(sender, e);
        }

        if (_originalPayloadForTamper is null)
        {
            MessageBox.Show("Сначала сформируйте или загрузите документ.", "Внимание", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        try
        {
            var tamperedDoc = TamperDocNumber.Text.Trim();
            var tamperedOwner = TamperOwner.Text.Trim();
            var issued = TamperIssuedPicker.SelectedDate.HasValue
                ? DateOnly.FromDateTime(TamperIssuedPicker.SelectedDate.Value)
                : _originalPayloadForTamper.Data.Issued;
            DateOnly? expires = TamperExpiresPicker.SelectedDate.HasValue
                ? DateOnly.FromDateTime(TamperExpiresPicker.SelectedDate.Value)
                : null;

            var tamperedData = new DocumentData(tamperedDoc, tamperedOwner, issued, expires);

            // АТАКА 1: Подменяем данные, но сохраняем оригинальную подпись
            var tamperedPayload = new SignedPayload(
                _originalPayloadForTamper.Version,
                _originalPayloadForTamper.Algorithm,
                _originalPayloadForTamper.KeyId,
                tamperedData,
                _originalPayloadForTamper.Signature
            );

            var tamperedJson = _codec.Encode(tamperedPayload);
            _encryptionService ??= new PayloadEncryptionService();
            var tamperedPayloadString = _encryptionService.Encrypt(tamperedJson);
            _tamperedQr = _qrService.Generate(tamperedPayloadString, pixels: 500, level: ErrorCorrectionLevel.Q);
            TamperedQrPreview.Source = _tamperedQr;

            TamperResultTitle.Text = "Сформирован образ: Атака 1 (подмена данных)";
            TamperResultDetails.Text = "В контейнер записаны измененные поля документа из Шага 1, но подпись оставлена старой. Нажмите «Отправить образ на проверку».";
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Ошибка: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void ToggleAttack2Panel_Click(object sender, RoutedEventArgs e)
    {
        Attack2SubPanel.Visibility = Attack2SubPanel.Visibility == Visibility.Visible
            ? Visibility.Collapsed
            : Visibility.Visible;

        if (Attack2SubPanel.Visibility == Visibility.Visible && _attackerPrivateKey is null)
        {
            GenerateAttackerKey_Click(sender, e);
        }
    }

    private void GenerateAttackerKey_Click(object sender, RoutedEventArgs e)
    {
        if (_keyManager is null) return;

        _attackerPrivateKey?.Dispose();
        _attackerPrivateKey = _keyManager.GenerateRsa(2048);
        var keyId = _keyManager.ComputeKeyId(_attackerPrivateKey);
        AttackerKeyIdDisplay.Text = $"Key ID атакующего: {keyId} (не доверен)";
    }

    private void ApplyAttack2_Click(object sender, RoutedEventArgs e)
    {
        if (_creationService is null || _codec is null || _qrService is null || _keyManager is null) return;

        try
        {
            if (_attackerPrivateKey is null)
            {
                GenerateAttackerKey_Click(sender, e);
            }

            var tamperedDoc = TamperDocNumber.Text.Trim();
            var tamperedOwner = TamperOwner.Text.Trim();
            var issued = TamperIssuedPicker.SelectedDate.HasValue
                ? DateOnly.FromDateTime(TamperIssuedPicker.SelectedDate.Value)
                : DateOnly.FromDateTime(DateTime.Today);
            DateOnly? expires = TamperExpiresPicker.SelectedDate.HasValue
                ? DateOnly.FromDateTime(TamperExpiresPicker.SelectedDate.Value)
                : null;

            var tamperedData = new DocumentData(
                string.IsNullOrEmpty(tamperedDoc) ? "DOC-ATTACK" : tamperedDoc,
                string.IsNullOrEmpty(tamperedOwner) ? "Неизвестный субъект" : tamperedOwner,
                issued,
                expires
            );

            // АТАКА 2: Подписываем ключом злоумышленника
            var signedByAttacker = _creationService.Create(tamperedData, _attackerPrivateKey!);
            var tamperedJson = _codec.Encode(signedByAttacker);
            _encryptionService ??= new PayloadEncryptionService();
            var tamperedPayloadString = _encryptionService.Encrypt(tamperedJson);

            _tamperedQr = _qrService.Generate(tamperedPayloadString, pixels: 500, level: ErrorCorrectionLevel.Q);
            TamperedQrPreview.Source = _tamperedQr;

            string keyName = string.IsNullOrWhiteSpace(AttackerKeyNameBox.Text) ? "Ключ злоумышленника" : AttackerKeyNameBox.Text.Trim();
            TamperResultTitle.Text = $"Сформирован образ: Атака 2 ({keyName})";
            TamperResultDetails.Text = $"Данные документа подписаны сторонним ключом (Key ID: {_keyManager.ComputeKeyId(_attackerPrivateKey!)}). Подпись математически верна, но ключ не доверен. Нажмите «Отправить образ на проверку».";
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Ошибка: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void TamperVerifyDirect_Click(object sender, RoutedEventArgs e)
    {
        if (_qrService is null || _verifier is null) return;

        if (_tamperedQr is null)
        {
            MessageBox.Show("Сначала сформируйте проверочный QR-код с помощью одной из кнопок атак выше.", "Внимание", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var decoded = _qrService.Decode(_tamperedQr);
        if (decoded is null)
        {
            TamperResultTitle.Text = "QR-код не распознан";
            TamperResultDetails.Text = "Декодер не смог считать матрицу QR-кода.";
            return;
        }

        var verification = _verifier.Verify(decoded);

        if (verification.Status == VerificationStatus.InvalidSignature)
        {
            TamperResultTitle.Text = "Результат проверки: Подделка обнаружена (подпись не совпала)";
            TamperResultDetails.Text = "Объяснение:\n" +
                "1. QR-код успешно распознан оптическим сканером.\n" +
                "2. Извлечены измененные данные документа и цифровая подпись.\n" +
                "3. Верификатор пересчитал хеш канонических данных, но проверка открытым ключом не прошла.\n" +
                "Вывод: Данные документа были изменены после подписания. Целостность нарушена.";
        }
        else if (verification.Status == VerificationStatus.UnknownKey)
        {
            TamperResultTitle.Text = "Результат проверки: Отклонено (ключ не доверен)";
            TamperResultDetails.Text = "Объяснение:\n" +
                "1. QR-код успешно распознан и содержит математически верную подпись.\n" +
                "2. Идентификатор ключа (Key ID) отсутствует в локальном списке доверенных ключей.\n" +
                "Вывод: Подпись сделана посторонним лицом, не имеющим полномочий издателя.";
        }
        else if (verification.Status == VerificationStatus.Valid)
        {
            TamperResultTitle.Text = "Результат проверки: Подлинность подтверждена";
            TamperResultDetails.Text = "Данные документа и цифровая подпись полностью соответствуют доверенному ключу.";
        }
        else
        {
            TamperResultTitle.Text = $"Результат проверки: {verification.Status}";
            TamperResultDetails.Text = verification.Message;
        }
    }
}
