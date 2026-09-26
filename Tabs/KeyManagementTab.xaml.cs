using System.Collections.ObjectModel;
using System.IO;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using QrAuthenticity.Cryptography;
using QrAuthenticity.Models;

namespace QrAuthenticity.Tabs;

public partial class KeyManagementTab : UserControl
{
    private KeyManager? _keyManager;
    private TrustedKeyStore? _trustedKeys;

    private readonly ObservableCollection<TrustedKeyEntry> _trustedKeyEntries = new();

    private string _currentWorkingKeyId = string.Empty;
    private string _currentWorkingKeyAlias = "Центральный орган сертификации";
    private RSA? _currentPrivateKey;

    public event Action<string>? KeyActivated;
    public event Action? KeyStoreChanged;
    public event Action<string?>? KeyDeleted;

    public KeyManagementTab()
    {
        InitializeComponent();
        TrustedKeysGrid.ItemsSource = _trustedKeyEntries;
    }

    public void Initialize(KeyManager keyManager, TrustedKeyStore trustedKeys)
    {
        _keyManager = keyManager;
        _trustedKeys = trustedKeys;
        RefreshTrustedKeysGrid();
    }

    public void RefreshTrustedKeysGrid()
    {
        if (_trustedKeys is null) return;

        _trustedKeyEntries.Clear();
        foreach (var entry in _trustedKeys.GetAllEntries())
        {
            _trustedKeyEntries.Add(entry);
        }
    }

    public void SyncWorkingKeyInfo(string keyId, string alias, int keySize, string publicPem, string privatePem, RSA? privateKey)
    {
        _currentWorkingKeyId = keyId;
        _currentWorkingKeyAlias = alias;
        _currentPrivateKey = privateKey;

        CurrentKeyIdBox.Text = keyId;
        KeyAliasInput.Text = alias;
        PublicKeyPreviewBox.Text = publicPem;
        PrivateKeyPreviewBox.Text = privatePem;
        KeySizeCombo.SelectedIndex = keySize == 3072 ? 1 : 0;
        AliasActionButtonsPanel.Visibility = Visibility.Collapsed;
    }

    private void GenerateNewKeyPair_Click(object sender, RoutedEventArgs e)
    {
        if (_keyManager is null || _trustedKeys is null) return;

        int keySize = KeySizeCombo.SelectedIndex == 1 ? 3072 : 2048;
        string alias = string.IsNullOrWhiteSpace(KeyAliasInput.Text) ? $"Издатель RSA-{keySize}" : KeyAliasInput.Text.Trim();

        _currentPrivateKey?.Dispose();
        _currentPrivateKey = _keyManager.GenerateRsa(keySize);

        var keyId = _keyManager.ComputeKeyId(_currentPrivateKey);
        _currentWorkingKeyId = keyId;
        _currentWorkingKeyAlias = alias;

        CurrentKeyIdBox.Text = keyId;
        KeyAliasInput.Text = alias;
        AliasActionButtonsPanel.Visibility = Visibility.Collapsed;

        var publicPem = _keyManager.ExportPublicPem(_currentPrivateKey);
        var privatePem = _keyManager.ExportPrivatePem(_currentPrivateKey);

        PublicKeyPreviewBox.Text = publicPem;
        PrivateKeyPreviewBox.Text = privatePem;

        _trustedKeys.SavePrivateKey(keyId, privatePem);
        _trustedKeys.AddPublicKey(publicPem, alias);
        RefreshTrustedKeysGrid();

        KeyActivated?.Invoke(keyId);
        KeyStoreChanged?.Invoke();

        MessageBox.Show($"Новая пара ключей сгенерирована.\nИздатель: {alias}\nKey ID: {keyId}", "Ключи готовы", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void ExportPrivateKey_Click(object sender, RoutedEventArgs e)
    {
        if (_currentPrivateKey is null || _keyManager is null)
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
        if (_currentPrivateKey is null || _keyManager is null)
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
        if (_keyManager is null || _trustedKeys is null) return;

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

                PrivateKeyPreviewBox.Text = pem;
                var publicPem = _keyManager.ExportPublicPem(_currentPrivateKey);
                PublicKeyPreviewBox.Text = publicPem;
                KeySizeCombo.SelectedIndex = _currentPrivateKey.KeySize == 3072 ? 1 : 0;

                _trustedKeys.SavePrivateKey(keyId, pem);
                _trustedKeys.AddPublicKey(publicPem, _currentWorkingKeyAlias);
                RefreshTrustedKeysGrid();

                KeyActivated?.Invoke(keyId);
                KeyStoreChanged?.Invoke();

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
        if (_currentPrivateKey is null || _keyManager is null || _trustedKeys is null)
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
        KeyStoreChanged?.Invoke();
        MessageBox.Show($"Открытый ключ «{alias}» добавлен в список доверенных.", "Успех", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void ImportTrustedKeyFile_Click(object sender, RoutedEventArgs e)
    {
        if (_trustedKeys is null) return;

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
                KeyStoreChanged?.Invoke();

                PublicKeyPreviewBox.Text = pem;
                MessageBox.Show($"Открытый ключ добавлен в список доверенных.\nИмя: {entry.Name}\nKey ID: {entry.KeyId}", "Ключ добавлен", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка чтения файла открытого ключа: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    private void DeleteAliasIconBtn_Click(object sender, RoutedEventArgs e)
    {
        DeleteSelectedTrustedKey();
    }

    private void DeleteSelectedTrustedKey()
    {
        if (_trustedKeys is null) return;

        if (TrustedKeysGrid.SelectedItem is TrustedKeyEntry selected)
        {
            var confirm = MessageBox.Show(
                $"Вы действительно хотите удалить ключ «{selected.Name}» (Key ID: {selected.KeyId})?",
                "Подтверждение удаления",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (confirm != MessageBoxResult.Yes)
            {
                return;
            }

            _trustedKeys.Remove(selected.KeyId);
            RefreshTrustedKeysGrid();

            string? nextWorkingId = null;
            if (string.Equals(selected.KeyId, _currentWorkingKeyId, StringComparison.OrdinalIgnoreCase))
            {
                var remaining = _trustedKeys.GetAllEntries();
                var nextWorking = remaining
                    .OrderByDescending(k => k.Id)
                    .FirstOrDefault(k => _trustedKeys.TryGetPrivateKeyPem(k.KeyId, out _));

                nextWorkingId = nextWorking?.KeyId;
            }

            KeyDeleted?.Invoke(nextWorkingId);
            KeyStoreChanged?.Invoke();

            TrustedKeysGrid.SelectedItem = null;
        }
        else
        {
            MessageBox.Show("Выберите ключ в таблице для удаления.", "Внимание", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private void TrustedKeysGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_trustedKeys is null || _keyManager is null) return;

        if (TrustedKeysGrid.SelectedItem is TrustedKeyEntry selected)
        {
            KeyAliasInput.Text = selected.Name;
            CurrentKeyIdBox.Text = selected.KeyId;
            PublicKeyPreviewBox.Text = selected.PublicPem;

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
        if (_trustedKeys is null) return;

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
            KeyStoreChanged?.Invoke();

            MessageBox.Show($"Имя ключа обновлено на «{newName}».", "Успех", MessageBoxButton.OK, MessageBoxImage.Information);

            TrustedKeysGrid.SelectedItem = null;
        }
    }

    private void CancelAliasIconBtn_Click(object sender, RoutedEventArgs e)
    {
        TrustedKeysGrid.SelectedItem = null;
    }

    private void SetActiveSigningKeyBtn_Click(object sender, RoutedEventArgs e)
    {
        if (_trustedKeys is null) return;

        if (TrustedKeysGrid.SelectedItem is TrustedKeyEntry selected)
        {
            if (!_trustedKeys.TryGetPrivateKeyPem(selected.KeyId, out var privatePem) || string.IsNullOrEmpty(privatePem))
            {
                MessageBox.Show(
                    $"Ключ «{selected.Name}» содержит только открытую часть (без закрытого ключа).\nОн используется проверяющей стороной для валидации, но не может создавать новые подписи.",
                    "Недоступно для подписи",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            KeyActivated?.Invoke(selected.KeyId);
            MessageBox.Show($"Ключ «{selected.Name}» (Key ID: {selected.KeyId}) выбран в качестве активного для создания подписей.", "Ключ активирован", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        else
        {
            MessageBox.Show("Выберите ключ из таблицы доверенных ключей.", "Внимание", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private void TrustedKeysGrid_MouseDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (_trustedKeys is null) return;

        if (TrustedKeysGrid.SelectedItem is TrustedKeyEntry selected &&
            _trustedKeys.TryGetPrivateKeyPem(selected.KeyId, out var privatePem) &&
            !string.IsNullOrEmpty(privatePem))
        {
            KeyActivated?.Invoke(selected.KeyId);
        }
    }
}
