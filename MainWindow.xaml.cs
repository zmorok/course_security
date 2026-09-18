using System.Collections.ObjectModel;
using System.IO;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Microsoft.Win32;
using QrAuthenticity.Cryptography;
using QrAuthenticity.Experiments;
using QrAuthenticity.Models;
using QrAuthenticity.QR;
using QrAuthenticity.Serialization;
using QrAuthenticity.Services;
using QrAuthenticity.Verification;
using ZXing.QrCode.Internal;

namespace QrAuthenticity;

public partial class MainWindow : Window
{
    private readonly KeyManager _keyManager = new();
    private readonly TrustedKeyStore _trustedKeys = new(persist: true);
    private readonly PayloadCanonicalizer _canonicalizer = new();
    private readonly PayloadCodec _codec = new();
    private readonly SignatureService _signatureService = new();
    private readonly PayloadCreationService _creationService;
    private readonly AuthenticityVerifier _verifier;
    private readonly QrCodeService _qrService = new();
    private readonly ImageDistortionService _distortionService = new();
    private readonly ExperimentRunner _experimentRunner;
    private readonly StatisticsService _statisticsService = new();

    private RSA? _currentPrivateKey;
    private string _currentWorkingKeyId = string.Empty;
    private string _currentWorkingKeyAlias = "Центральный орган сертификации";
    private BitmapSource? _currentGeneratedQr;
    private SignedPayload? _currentSignedPayload;
    private string? _currentPayloadJson;

    private BitmapSource? _loadedVerificationQr;
    private BitmapSource? _tamperedQr;
    private SignedPayload? _originalPayloadForTamper;
    private RSA? _attackerPrivateKey;

    private readonly ObservableCollection<TrustedKeyEntry> _trustedKeyEntries = new();
    private readonly ObservableCollection<ExperimentResult> _experimentResults = new();

    public MainWindow()
    {
        InitializeComponent();

        _creationService = new PayloadCreationService(_keyManager, _signatureService, _canonicalizer, _codec);
        _verifier = new AuthenticityVerifier(_codec, _canonicalizer, _signatureService, _trustedKeys);
        _experimentRunner = new ExperimentRunner(_distortionService, _qrService, _verifier);

        TrustedKeysGrid.ItemsSource = _trustedKeyEntries;
        ExperimentResultsGrid.ItemsSource = _experimentResults;

        InitializeDefaultState();
    }

    private void InitializeDefaultState()
    {
        DocIssuedPicker.SelectedDate = DateTime.Today;
        DocExpiresPicker.SelectedDate = DateTime.Today.AddYears(5);

        DistortionTypeCombo.ItemsSource = ImageDistortionService.AvailableDistortions;
        DistortionTypeCombo.SelectedItem = ImageDistortionService.DistortionOcclusion;

        // Если в хранилище уже есть ранее сохраненные ключи - восстанавливаем активный ключ
        var existingEntries = _trustedKeys.GetAllEntries();
        var activeEntry = existingEntries.Count > 0
            ? existingEntries.OrderByDescending(e => e.Id).FirstOrDefault(e => _trustedKeys.TryGetPrivateKeyPem(e.KeyId, out _))
            : null;

        if (activeEntry is not null && _trustedKeys.TryGetPrivateKeyPem(activeEntry.KeyId, out var savedPrivatePem) && !string.IsNullOrEmpty(savedPrivatePem))
        {
            _currentPrivateKey?.Dispose();
            _currentPrivateKey = _keyManager.ImportPrivatePem(savedPrivatePem);

            _currentWorkingKeyId = activeEntry.KeyId;
            _currentWorkingKeyAlias = activeEntry.Name;

            CurrentKeyIdBox.Text = activeEntry.KeyId;
            KeyAliasInput.Text = activeEntry.Name;
            AliasActionButtonsPanel.Visibility = Visibility.Collapsed;
            CreationKeyIdDisplay.Text = activeEntry.KeyId;

            PublicKeyPreviewBox.Text = activeEntry.PublicPem;
            PrivateKeyPreviewBox.Text = savedPrivatePem;

            RefreshTrustedKeysGrid();
        }
        else
        {
            // Создаем начальный доверенный ключ при первом запуске
            string alias = string.IsNullOrWhiteSpace(KeyAliasInput.Text) ? "Центральный орган сертификации" : KeyAliasInput.Text.Trim();
            GenerateAndSetWorkingKey(2048, alias);
        }

        // Автоматически формируем первый валидный QR-код
        CreateSignedQr();
        CopyCurrentToTamperLab();
    }

    private void GenerateAndSetWorkingKey(int keySize, string keyAlias)
    {
        _currentPrivateKey?.Dispose();
        _currentPrivateKey = _keyManager.GenerateRsa(keySize);

        var keyId = _keyManager.ComputeKeyId(_currentPrivateKey);
        _currentWorkingKeyId = keyId;
        _currentWorkingKeyAlias = keyAlias;

        CurrentKeyIdBox.Text = keyId;
        KeyAliasInput.Text = keyAlias;
        AliasActionButtonsPanel.Visibility = Visibility.Collapsed;
        CreationKeyIdDisplay.Text = keyId;

        var publicPem = _keyManager.ExportPublicPem(_currentPrivateKey);
        var privatePem = _keyManager.ExportPrivatePem(_currentPrivateKey);

        // Обновляем предпросмотр ключей
        PublicKeyPreviewBox.Text = publicPem;
        PrivateKeyPreviewBox.Text = privatePem;

        // Сохраняем закрытый ключ на диск и регистрируем в реестре
        _trustedKeys.SavePrivateKey(keyId, privatePem);
        _trustedKeys.AddPublicKey(publicPem, keyAlias);
        RefreshTrustedKeysGrid();
    }

    private void RefreshTrustedKeysGrid()
    {
        _trustedKeyEntries.Clear();
        foreach (var entry in _trustedKeys.GetAllEntries())
        {
            _trustedKeyEntries.Add(entry);
        }
    }

    // =========================================================================
    // Вкладка 1: Создание подписанного QR-кода
    // =========================================================================

    private void CreateSignedQr_Click(object sender, RoutedEventArgs e)
    {
        CreateSignedQr();
    }

    private void CreateSignedQr()
    {
        try
        {
            if (_currentPrivateKey is null)
            {
                string alias = string.IsNullOrWhiteSpace(KeyAliasInput.Text) ? "Издатель документов" : KeyAliasInput.Text.Trim();
                GenerateAndSetWorkingKey(2048, alias);
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
            _currentSignedPayload = _creationService.Create(documentData, _currentPrivateKey!);
            _currentPayloadJson = _codec.Encode(_currentSignedPayload);

            CreationJsonPreview.Text = _currentPayloadJson;
            CreationKeyIdDisplay.Text = _currentSignedPayload.KeyId;

            var ecLevel = GetSelectedErrorCorrectionLevel();
            _currentGeneratedQr = _qrService.Generate(_currentPayloadJson, pixels: 600, level: ecLevel);
            GeneratedQrImage.Source = _currentGeneratedQr;

            int payloadBytes = System.Text.Encoding.UTF8.GetByteCount(_currentPayloadJson);
            QrMetricsLabel.Text = $"Размер данных: {payloadBytes} байт | Коррекция Рида-Соломона: {ecLevel} | Разрешение: {_currentGeneratedQr.PixelWidth}x{_currentGeneratedQr.PixelHeight}";

            CopyCurrentToTamperLab();
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
                _qrService.SavePng(_currentGeneratedQr, dialog.FileName);
                MessageBox.Show($"QR-код успешно сохранен:\n{dialog.FileName}", "Файл сохранен", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Не удалось сохранить файл: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    // =========================================================================
    // Вкладка 2: Проверка подлинности и целостности
    // =========================================================================

    private void LoadVerificationQr_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Выберите изображение QR-кода для проверки",
            Filter = "Изображения (*.png;*.jpg;*.jpeg;*.bmp)|*.png;*.jpg;*.jpeg;*.bmp"
        };

        if (dialog.ShowDialog() == true)
        {
            try
            {
                _loadedVerificationQr = _qrService.Load(dialog.FileName);
                VerificationQrImage.Source = _loadedVerificationQr;
                ResetVerificationDisplay();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка открытия изображения: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    private void UseCurrentGeneratedForVerify_Click(object sender, RoutedEventArgs e)
    {
        if (_currentGeneratedQr is null)
        {
            CreateSignedQr();
        }

        _loadedVerificationQr = _currentGeneratedQr;
        VerificationQrImage.Source = _loadedVerificationQr;
        ResetVerificationDisplay();
    }

    private void ResetVerificationDisplay()
    {
        VerificationStatusHeading.Text = "Изображение загружено";
        VerificationStatusHeading.Foreground = new SolidColorBrush(Color.FromRgb(36, 41, 47));
        StatusBadgeBorder.Background = new SolidColorBrush(Color.FromRgb(246, 248, 250));
        StatusBadgeBorder.BorderBrush = new SolidColorBrush(Color.FromRgb(208, 215, 222));
        VerificationMessageDetail.Text = "Нажмите «Проверить цифровую подпись» для запуска анализа.";

        ResultDocNumber.Text = "—";
        ResultOwner.Text = "—";
        ResultIssued.Text = "—";
        ResultExpires.Text = "—";
        ResultKeyId.Text = "—";
        ResultKeyTrustStatus.Text = "—";
        DecodedRawJsonText.Text = string.Empty;
    }

    private void RunVerification_Click(object sender, RoutedEventArgs e)
    {
        if (_loadedVerificationQr is null)
        {
            MessageBox.Show("Загрузите изображение QR-кода или воспользуйтесь кнопкой «Взять сгенерированный».", "Внимание", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var decodedText = _qrService.Decode(_loadedVerificationQr);

        if (decodedText is null)
        {
            SetStatusBadge(
                "QR-КОД НЕ РАСПОЗНАН",
                "Декодер не смог прочитать QR-код. Возможно, изображение повреждено или сильно размыто.",
                Color.FromRgb(246, 248, 250),
                Color.FromRgb(87, 96, 106),
                Color.FromRgb(208, 215, 222)
            );
            return;
        }

        DecodedRawJsonText.Text = decodedText;
        var result = _verifier.Verify(decodedText);

        if (result.Payload is not null)
        {
            ResultDocNumber.Text = result.Payload.Data.DocumentNumber;
            ResultOwner.Text = result.Payload.Data.Owner;
            ResultIssued.Text = result.Payload.Data.Issued.ToString("yyyy-MM-dd");
            ResultExpires.Text = result.Payload.Data.Expires?.ToString("yyyy-MM-dd") ?? "Бессрочный";
            ResultKeyId.Text = result.Payload.KeyId;

            bool isTrusted = _trustedKeys.TryGet(result.Payload.KeyId, out _);
            ResultKeyTrustStatus.Text = isTrusted ? "Ключ в списке доверенных" : "Неизвестный ключ (не доверен)";
            ResultKeyTrustStatus.Foreground = isTrusted
                ? new SolidColorBrush(Color.FromRgb(26, 127, 55))
                : new SolidColorBrush(Color.FromRgb(207, 34, 46));
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

    // =========================================================================
    // Вкладка 3: Демонстрация атак
    // =========================================================================

    private void CopyCurrentToTamperLab()
    {
        if (_currentSignedPayload is null) return;

        _originalPayloadForTamper = _currentSignedPayload;
        TamperDocNumber.Text = _currentSignedPayload.Data.DocumentNumber;
        TamperOwner.Text = _currentSignedPayload.Data.Owner;
        TamperIssuedPicker.SelectedDate = _currentSignedPayload.Data.Issued.ToDateTime(TimeOnly.MinValue);
        TamperExpiresPicker.SelectedDate = _currentSignedPayload.Data.Expires?.ToDateTime(TimeOnly.MinValue);
    }

    private void TamperLoadCurrent_Click(object sender, RoutedEventArgs e)
    {
        if (_currentSignedPayload is null)
        {
            CreateSignedQr();
        }
        CopyCurrentToTamperLab();
    }

    private void TamperLoadImage_Click(object sender, RoutedEventArgs e)
    {
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

                _originalPayloadForTamper = _codec.Decode(text);
                TamperDocNumber.Text = _originalPayloadForTamper.Data.DocumentNumber;
                TamperOwner.Text = _originalPayloadForTamper.Data.Owner;
                TamperIssuedPicker.SelectedDate = _originalPayloadForTamper.Data.Issued.ToDateTime(TimeOnly.MinValue);
                TamperExpiresPicker.SelectedDate = _originalPayloadForTamper.Data.Expires?.ToDateTime(TimeOnly.MinValue);

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
            CopyCurrentToTamperLab();
        }
    }

    private void TamperAttackOldSig_Click(object sender, RoutedEventArgs e)
    {
        if (_originalPayloadForTamper is null)
        {
            CreateSignedQr();
        }

        try
        {
            var tamperedDoc = TamperDocNumber.Text.Trim();
            var tamperedOwner = TamperOwner.Text.Trim();
            var issued = TamperIssuedPicker.SelectedDate.HasValue
                ? DateOnly.FromDateTime(TamperIssuedPicker.SelectedDate.Value)
                : _originalPayloadForTamper!.Data.Issued;
            DateOnly? expires = TamperExpiresPicker.SelectedDate.HasValue
                ? DateOnly.FromDateTime(TamperExpiresPicker.SelectedDate.Value)
                : null;

            var tamperedData = new DocumentData(tamperedDoc, tamperedOwner, issued, expires);

            // АТАКА 1: Подменяем данные, но сохраняем оригинальную подпись
            var tamperedPayload = new SignedPayload(
                _originalPayloadForTamper!.Version,
                _originalPayloadForTamper.Algorithm,
                _originalPayloadForTamper.KeyId,
                tamperedData,
                _originalPayloadForTamper.Signature
            );

            var tamperedJson = _codec.Encode(tamperedPayload);
            _tamperedQr = _qrService.Generate(tamperedJson, pixels: 500, level: ErrorCorrectionLevel.Q);
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
        _attackerPrivateKey?.Dispose();
        _attackerPrivateKey = _keyManager.GenerateRsa(2048);
        var keyId = _keyManager.ComputeKeyId(_attackerPrivateKey);
        AttackerKeyIdDisplay.Text = $"Key ID атакующего: {keyId} (не доверен)";
    }

    private void ApplyAttack2_Click(object sender, RoutedEventArgs e)
    {
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

            _tamperedQr = _qrService.Generate(tamperedJson, pixels: 500, level: ErrorCorrectionLevel.Q);
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

    // =========================================================================
    // Вкладка 4: Управление ключами
    // =========================================================================

    private void GenerateNewKeyPair_Click(object sender, RoutedEventArgs e)
    {
        int keySize = KeySizeCombo.SelectedIndex == 1 ? 3072 : 2048;
        string alias = string.IsNullOrWhiteSpace(KeyAliasInput.Text) ? $"Издатель RSA-{keySize}" : KeyAliasInput.Text.Trim();
        GenerateAndSetWorkingKey(keySize, alias);
        MessageBox.Show($"Новая пара ключей сгенерирована.\nИздатель: {alias}\nKey ID: {CurrentKeyIdBox.Text}", "Ключи готовы", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void ExportPrivateKey_Click(object sender, RoutedEventArgs e)
    {
        if (_currentPrivateKey is null)
        {
            MessageBox.Show("Ключевая пара еще не создана.", "Внимание", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var dialog = new SaveFileDialog
        {
            Title = "Сохранение закрытого ключа в файл",
            Filter = "Файл ключа PEM (*.pem)|*.pem|Все файлы (*.*)|*.*",
            FileName = $"private_key_{CurrentKeyIdBox.Text}.pem"
        };

        if (dialog.ShowDialog() == true)
        {
            _keyManager.SavePrivatePem(_currentPrivateKey, dialog.FileName);
            MessageBox.Show("Закрытый ключ успешно сохранен в файл.", "Успех", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private void ExportPublicKey_Click(object sender, RoutedEventArgs e)
    {
        if (_currentPrivateKey is null)
        {
            MessageBox.Show("Ключевая пара еще не создана.", "Внимание", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var dialog = new SaveFileDialog
        {
            Title = "Сохранение открытого ключа в файл",
            Filter = "Файл ключа PEM (*.pem)|*.pem|Все файлы (*.*)|*.*",
            FileName = $"public_key_{CurrentKeyIdBox.Text}.pem"
        };

        if (dialog.ShowDialog() == true)
        {
            _keyManager.SavePublicPem(_currentPrivateKey, dialog.FileName);
            MessageBox.Show("Открытый ключ успешно сохранен в файл.", "Успех", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private void ImportPrivateKey_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Выберите файл закрытого ключа (PEM)",
            Filter = "Файл ключа PEM (*.pem)|*.pem|Все файлы (*.*)|*.*"
        };

        if (dialog.ShowDialog() == true)
        {
            try
            {
                var pem = File.ReadAllText(dialog.FileName);
                _currentPrivateKey?.Dispose();
                _currentPrivateKey = _keyManager.ImportPrivatePem(pem);

                var keyId = _keyManager.ComputeKeyId(_currentPrivateKey);
                _currentWorkingKeyId = keyId;
                _currentWorkingKeyAlias = Path.GetFileNameWithoutExtension(dialog.FileName);

                CurrentKeyIdBox.Text = keyId;
                KeyAliasInput.Text = _currentWorkingKeyAlias;
                AliasActionButtonsPanel.Visibility = Visibility.Collapsed;
                CreationKeyIdDisplay.Text = keyId;

                PrivateKeyPreviewBox.Text = pem;
                var publicPem = _keyManager.ExportPublicPem(_currentPrivateKey);
                PublicKeyPreviewBox.Text = publicPem;

                _trustedKeys.SavePrivateKey(keyId, pem);
                _trustedKeys.AddPublicKey(publicPem, _currentWorkingKeyAlias);
                RefreshTrustedKeysGrid();

                MessageBox.Show($"Закрытый ключ успешно загружен.\nKey ID: {keyId}", "Ключ загружен", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка загрузки закрытого ключа: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    private void AddCurrentKeyToTrusted_Click(object sender, RoutedEventArgs e)
    {
        if (_currentPrivateKey is null)
        {
            MessageBox.Show("Сначала создайте или загрузите ключ.", "Внимание", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        string alias = string.IsNullOrWhiteSpace(KeyAliasInput.Text) ? "Текущий издатель" : KeyAliasInput.Text.Trim();
        if (TrustedKeysGrid.SelectedItem is null)
        {
            _currentWorkingKeyAlias = alias;
        }

        var publicPem = _keyManager.ExportPublicPem(_currentPrivateKey);
        _trustedKeys.AddPublicKey(publicPem, alias);
        RefreshTrustedKeysGrid();
        MessageBox.Show($"Открытый ключ «{alias}» добавлен в список доверенных.", "Успех", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void ImportTrustedKeyFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Импорт открытого ключа в доверенные",
            Filter = "Файл ключа PEM (*.pem)|*.pem|Все файлы (*.*)|*.*"
        };

        if (dialog.ShowDialog() == true)
        {
            try
            {
                var pem = File.ReadAllText(dialog.FileName);
                var alias = Path.GetFileNameWithoutExtension(dialog.FileName);
                var entry = _trustedKeys.AddPublicKey(pem, alias);
                RefreshTrustedKeysGrid();
                PublicKeyPreviewBox.Text = pem;
                MessageBox.Show($"Открытый ключ добавлен в список доверенных.\nИмя: {entry.Name}\nKey ID: {entry.KeyId}", "Ключ добавлен", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка чтения файла открытого ключа: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    private void RemoveTrustedKey_Click(object sender, RoutedEventArgs e)
    {
        if (TrustedKeysGrid.SelectedItem is TrustedKeyEntry selected)
        {
            if (MessageBox.Show($"Удалить доверенный ключ «{selected.Name}» (Key ID: {selected.KeyId})?", "Подтверждение", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
            {
                _trustedKeys.Remove(selected.KeyId);
                RefreshTrustedKeysGrid();
                TrustedKeysGrid.SelectedItem = null;
            }
        }
        else
        {
            MessageBox.Show("Выберите ключ в таблице для удаления.", "Внимание", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private void TrustedKeysGrid_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (TrustedKeysGrid.SelectedItem is TrustedKeyEntry selected)
        {
            KeyAliasInput.Text = selected.Name;
            CurrentKeyIdBox.Text = selected.KeyId;
            PublicKeyPreviewBox.Text = selected.PublicPem;

            // Проверяем наличие закрытого ключа в локальном хранилище ключей
            if (_trustedKeys.TryGetPrivateKeyPem(selected.KeyId, out var privatePem) && !string.IsNullOrEmpty(privatePem))
            {
                PrivateKeyPreviewBox.Text = privatePem;
            }
            else if (_currentPrivateKey is not null && string.Equals(selected.KeyId, _currentWorkingKeyId, StringComparison.OrdinalIgnoreCase))
            {
                PrivateKeyPreviewBox.Text = _keyManager.ExportPrivatePem(_currentPrivateKey);
            }
            else
            {
                PrivateKeyPreviewBox.Text = "(Закрытый ключ отсутствует на этом устройстве. Это внешний доверенный открытый ключ проверяющей стороны)";
            }

            AliasActionButtonsPanel.Visibility = Visibility.Visible;
        }
        else
        {
            KeyAliasInput.Text = _currentWorkingKeyAlias;
            CurrentKeyIdBox.Text = _currentWorkingKeyId;

            if (_currentPrivateKey is not null)
            {
                PublicKeyPreviewBox.Text = _keyManager.ExportPublicPem(_currentPrivateKey);
                PrivateKeyPreviewBox.Text = _keyManager.ExportPrivatePem(_currentPrivateKey);
            }
            else
            {
                PublicKeyPreviewBox.Text = string.Empty;
                PrivateKeyPreviewBox.Text = string.Empty;
            }

            AliasActionButtonsPanel.Visibility = Visibility.Collapsed;
        }
    }

    private void SaveAliasIconBtn_Click(object sender, RoutedEventArgs e)
    {
        if (TrustedKeysGrid.SelectedItem is TrustedKeyEntry selected)
        {
            string newName = KeyAliasInput.Text.Trim();
            if (string.IsNullOrWhiteSpace(newName))
            {
                MessageBox.Show("Имя ключа не может быть пустым.", "Предупреждение", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            string targetKeyId = selected.KeyId;
            _trustedKeys.UpdateName(targetKeyId, newName);

            if (string.Equals(targetKeyId, _currentWorkingKeyId, StringComparison.OrdinalIgnoreCase))
            {
                _currentWorkingKeyAlias = newName;
            }

            RefreshTrustedKeysGrid();

            // Восстанавливаем выделение обновленной записи в таблице
            var refreshed = _trustedKeyEntries.FirstOrDefault(k => string.Equals(k.KeyId, targetKeyId, StringComparison.OrdinalIgnoreCase));
            if (refreshed is not null)
            {
                TrustedKeysGrid.SelectedItem = refreshed;
            }

            MessageBox.Show($"Имя ключа обновлено на «{newName}».", "Успех", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private void CancelAliasIconBtn_Click(object sender, RoutedEventArgs e)
    {
        TrustedKeysGrid.SelectedItem = null;
    }

    // =========================================================================
    // Вкладка 5: Эксперименты и надежность
    // =========================================================================

    private void DistortionTypeCombo_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (DistortionTypeCombo.SelectedItem is not string selected) return;

        switch (selected)
        {
            case ImageDistortionService.DistortionRotate:
                ExpStartBox.Text = "0"; ExpEndBox.Text = "45"; ExpStepBox.Text = "5";
                break;
            case ImageDistortionService.DistortionScale:
                ExpStartBox.Text = "0"; ExpEndBox.Text = "80"; ExpStepBox.Text = "10";
                break;
            case ImageDistortionService.DistortionOcclusion:
                ExpStartBox.Text = "0"; ExpEndBox.Text = "35"; ExpStepBox.Text = "5";
                break;
            case ImageDistortionService.DistortionNoise:
                ExpStartBox.Text = "0"; ExpEndBox.Text = "20"; ExpStepBox.Text = "2";
                break;
            case ImageDistortionService.DistortionBlur:
                ExpStartBox.Text = "1"; ExpEndBox.Text = "8"; ExpStepBox.Text = "1";
                break;
            case ImageDistortionService.DistortionContrast:
                ExpStartBox.Text = "0"; ExpEndBox.Text = "90"; ExpStepBox.Text = "10";
                break;
            case ImageDistortionService.DistortionJpeg:
                ExpStartBox.Text = "0"; ExpEndBox.Text = "95"; ExpStepBox.Text = "10";
                break;
        }
    }

    private async void StartExperimentSeries_Click(object sender, RoutedEventArgs e)
    {
        if (_currentGeneratedQr is null)
        {
            CreateSignedQr();
        }

        var sourceImage = _currentGeneratedQr!;
        var distortion = DistortionTypeCombo.SelectedItem as string ?? ImageDistortionService.DistortionOcclusion;

        if (!double.TryParse(ExpStartBox.Text, out double start) ||
            !double.TryParse(ExpEndBox.Text, out double end) ||
            !double.TryParse(ExpStepBox.Text, out double step) ||
            !int.TryParse(ExpAttemptsBox.Text, out int attempts) ||
            !int.TryParse(ExpSeedBox.Text, out int seed))
        {
            MessageBox.Show("Проверьте числовые параметры серии.", "Ошибка ввода", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        StartExperimentBtn.IsEnabled = false;
        ExperimentProgressBar.Visibility = Visibility.Visible;
        ExperimentProgressBar.Value = 0;
        ExperimentStatusLabel.Text = "Выполняются измерения...";

        _experimentResults.Clear();

        await Task.Run(() =>
        {
            _experimentRunner.RunSeries(
                sourceImage,
                distortion,
                start,
                end,
                step,
                attempts,
                seed,
                (stepIdx, totalSteps, pointResult) =>
                {
                    Dispatcher.Invoke(() =>
                    {
                        _experimentResults.Add(pointResult);
                        ExperimentProgressBar.Value = (double)stepIdx / totalSteps * 100.0;
                        ExperimentStatusLabel.Text = $"Шаг: {stepIdx} из {totalSteps}. Интенсивность: {pointResult.Intensity} (P_decode: {pointResult.DecodeRate:P0})";

                        var sample = _distortionService.Apply(sourceImage, distortion, pointResult.Intensity, seed);
                        DistortedSamplePreview.Source = sample;
                    });
                }
            );
        });

        StartExperimentBtn.IsEnabled = true;
        ExperimentProgressBar.Visibility = Visibility.Collapsed;
        ExperimentStatusLabel.Text = $"Серия завершена. Записей: {_experimentResults.Count}. Можно выгрузить в CSV.";
    }

    private void ExportCsv_Click(object sender, RoutedEventArgs e)
    {
        if (_experimentResults.Count == 0)
        {
            MessageBox.Show("Сначала запустите серию измерений.", "Внимание", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var dialog = new SaveFileDialog
        {
            Title = "Сохранение результатов в CSV",
            Filter = "Файл CSV (*.csv)|*.csv|Все файлы (*.*)|*.*",
            FileName = "experiment_results.csv"
        };

        if (dialog.ShowDialog() == true)
        {
            try
            {
                var csv = _statisticsService.ToCsv(_experimentResults);
                File.WriteAllText(dialog.FileName, csv, System.Text.Encoding.UTF8);
                MessageBox.Show($"Файл CSV успешно сохранен:\n{dialog.FileName}", "Успех", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка сохранения CSV: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    private void ClearExperimentResults_Click(object sender, RoutedEventArgs e)
    {
        _experimentResults.Clear();
        DistortedSamplePreview.Source = null;
        ExperimentStatusLabel.Text = "Результаты очищены.";
    }

    protected override void OnClosed(EventArgs e)
    {
        _currentPrivateKey?.Dispose();
        _attackerPrivateKey?.Dispose();
        _trustedKeys.Dispose();
        base.OnClosed(e);
    }
}
