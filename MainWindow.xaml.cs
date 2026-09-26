using System.Security.Cryptography;
using System.Windows;
using QrAuthenticity.Cryptography;
using QrAuthenticity.Experiments;
using QrAuthenticity.Models;
using QrAuthenticity.QR;
using QrAuthenticity.Serialization;
using QrAuthenticity.Services;
using QrAuthenticity.Verification;

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

    private RSA? _currentPrivateKey;
    private string _currentWorkingKeyId = string.Empty;
    private string _currentWorkingKeyAlias = "Центральный орган сертификации";

    public MainWindow()
    {
        InitializeComponent();

        _creationService = new PayloadCreationService(_keyManager, _signatureService, _canonicalizer, _codec);
        _verifier = new AuthenticityVerifier(_codec, _canonicalizer, _signatureService, _trustedKeys);
        _experimentRunner = new ExperimentRunner(_distortionService, _qrService, _verifier);

        InitializeTabs();
        InitializeDefaultState();
    }

    private void InitializeTabs()
    {
        // 1. Вкладка создания QR-кода
        CreationTab.Initialize(_creationService, _codec, _qrService);
        CreationTab.KeySelectionChanged += keyId => SwitchWorkingKey(keyId);
        CreationTab.QrCreated += (payload, image, json) =>
        {
            AttackLabTab.LoadCurrentDocument(payload, image);
        };

        // 2. Вкладка проверки подлинности
        VerificationTab.Initialize(_qrService, _verifier, _trustedKeys);
        VerificationTab.GetCurrentGeneratedQr = () => CreationTab.CurrentGeneratedQr;

        // 3. Вкладка лаборатории атак
        AttackLabTab.Initialize(_keyManager, _creationService, _codec, _qrService, _verifier);
        AttackLabTab.RequestCurrentPayload = () => (CreationTab.CurrentSignedPayload, CreationTab.CurrentGeneratedQr);

        // 4. Вкладка управления ключами
        KeyManagementTab.Initialize(_keyManager, _trustedKeys);
        KeyManagementTab.KeyActivated += keyId => SwitchWorkingKey(keyId);
        KeyManagementTab.KeyStoreChanged += () => RefreshCreationTabKeys();
        KeyManagementTab.KeyDeleted += nextKeyId => HandleKeyDeleted(nextKeyId);

        // 5. Вкладка экспериментов
        ExperimentsTab.Initialize(_distortionService, _qrService, _experimentRunner);
        ExperimentsTab.GetSourceQrImage = () =>
        {
            if (CreationTab.CurrentGeneratedQr is null)
            {
                CreationTab.CreateSignedQr();
            }
            return CreationTab.CurrentGeneratedQr;
        };
    }

    private void InitializeDefaultState()
    {
        // Восстанавливаем последний активный ключ из реестра или генерируем новый
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

            CreationTab.SetWorkingKey(_currentPrivateKey, activeEntry.KeyId, activeEntry.Name);
            KeyManagementTab.SyncWorkingKeyInfo(activeEntry.KeyId, activeEntry.Name, _currentPrivateKey.KeySize, activeEntry.PublicPem, savedPrivatePem, _currentPrivateKey);
            RefreshCreationTabKeys();
        }
        else
        {
            GenerateAndSetWorkingKey(2048, "Центральный орган сертификации");
        }

        CreationTab.CreateSignedQr();
        AttackLabTab.LoadCurrentDocument(CreationTab.CurrentSignedPayload, CreationTab.CurrentGeneratedQr);
    }

    private void GenerateAndSetWorkingKey(int keySize, string keyAlias)
    {
        _currentPrivateKey?.Dispose();
        _currentPrivateKey = _keyManager.GenerateRsa(keySize);

        var keyId = _keyManager.ComputeKeyId(_currentPrivateKey);
        _currentWorkingKeyId = keyId;
        _currentWorkingKeyAlias = keyAlias;

        var publicPem = _keyManager.ExportPublicPem(_currentPrivateKey);
        var privatePem = _keyManager.ExportPrivatePem(_currentPrivateKey);

        _trustedKeys.SavePrivateKey(keyId, privatePem);
        _trustedKeys.AddPublicKey(publicPem, keyAlias);

        CreationTab.SetWorkingKey(_currentPrivateKey, keyId, keyAlias);
        KeyManagementTab.RefreshTrustedKeysGrid();
        KeyManagementTab.SyncWorkingKeyInfo(keyId, keyAlias, keySize, publicPem, privatePem, _currentPrivateKey);
        RefreshCreationTabKeys();
    }

    private void SwitchWorkingKey(string keyId)
    {
        if (string.Equals(_currentWorkingKeyId, keyId, StringComparison.OrdinalIgnoreCase) && _currentPrivateKey is not null)
        {
            CreationTab.UpdateAlgorithmDisplay();
            return;
        }

        if (_trustedKeys.TryGetPrivateKeyPem(keyId, out var privatePem) && !string.IsNullOrEmpty(privatePem))
        {
            var entries = _trustedKeys.GetAllEntries();
            var entry = entries.FirstOrDefault(e => string.Equals(e.KeyId, keyId, StringComparison.OrdinalIgnoreCase));
            string name = entry?.Name ?? "Ключ";

            _currentPrivateKey?.Dispose();
            _currentPrivateKey = _keyManager.ImportPrivatePem(privatePem);
            _currentWorkingKeyId = keyId;
            _currentWorkingKeyAlias = name;

            CreationTab.SetWorkingKey(_currentPrivateKey, keyId, name);
            KeyManagementTab.SyncWorkingKeyInfo(keyId, name, _currentPrivateKey.KeySize, entry?.PublicPem ?? _keyManager.ExportPublicPem(_currentPrivateKey), privatePem, _currentPrivateKey);
            RefreshCreationTabKeys();

            CreationTab.CreateSignedQr();
        }
    }

    private void RefreshCreationTabKeys()
    {
        var signingKeys = new List<SigningKeyOption>();

        foreach (var entry in _trustedKeys.GetAllEntries())
        {
            if (_trustedKeys.TryGetPrivateKeyPem(entry.KeyId, out var privPem) && !string.IsNullOrEmpty(privPem))
            {
                int keySize = 2048;
                if (_trustedKeys.TryGet(entry.KeyId, out var rsa) && rsa is not null)
                {
                    keySize = rsa.KeySize;
                }
                else
                {
                    try
                    {
                        using var tempRsa = _keyManager.ImportPrivatePem(privPem);
                        keySize = tempRsa.KeySize;
                    }
                    catch
                    {
                    }
                }

                signingKeys.Add(new SigningKeyOption(entry.KeyId, entry.Name, keySize, entry.PublicPem));
            }
        }

        if (!string.IsNullOrEmpty(_currentWorkingKeyId) &&
            _currentPrivateKey is not null &&
            !signingKeys.Any(k => string.Equals(k.KeyId, _currentWorkingKeyId, StringComparison.OrdinalIgnoreCase)))
        {
            signingKeys.Add(new SigningKeyOption(
                _currentWorkingKeyId,
                _currentWorkingKeyAlias,
                _currentPrivateKey.KeySize,
                _keyManager.ExportPublicPem(_currentPrivateKey)));
        }

        CreationTab.RefreshKeyOptions(signingKeys, _currentWorkingKeyId);
    }

    private void HandleKeyDeleted(string? nextKeyId)
    {
        if (!string.IsNullOrEmpty(nextKeyId))
        {
            SwitchWorkingKey(nextKeyId);
        }
        else
        {
            _currentPrivateKey?.Dispose();
            _currentPrivateKey = null;
            _currentWorkingKeyId = string.Empty;
            _currentWorkingKeyAlias = string.Empty;

            RefreshCreationTabKeys();
        }
    }

    protected override void OnClosed(EventArgs e)
    {
        _currentPrivateKey?.Dispose();
        _trustedKeys.Dispose();
        base.OnClosed(e);
    }
}
