using System.Collections.ObjectModel;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Imaging;
using Microsoft.Win32;
using QrAuthenticity.Experiments;
using QrAuthenticity.Models;
using QrAuthenticity.QR;
using QrAuthenticity.Services;

namespace QrAuthenticity.Tabs;

public partial class ExperimentsTab : UserControl
{
    private ImageDistortionService? _distortionService;
    private QrCodeService? _qrService;
    private ExperimentRunner? _experimentRunner;
    private readonly StatisticsService _statisticsService = new();

    private readonly ObservableCollection<ExperimentResult> _experimentResults = new();
    private BitmapSource? _lastExperimentSourceImage;
    private BitmapSource? _currentDistortedSample;
    private CancellationTokenSource? _experimentCts;

    public Func<BitmapSource?>? GetSourceQrImage { get; set; }

    public ExperimentsTab()
    {
        InitializeComponent();
        ExperimentResultsGrid.ItemsSource = _experimentResults;
        DistortionTypeCombo.ItemsSource = ImageDistortionService.AvailableDistortions;
        DistortionTypeCombo.SelectedItem = ImageDistortionService.DistortionOcclusion;
    }

    public void Initialize(
        ImageDistortionService distortionService,
        QrCodeService qrService,
        ExperimentRunner experimentRunner)
    {
        _distortionService = distortionService;
        _qrService = qrService;
        _experimentRunner = experimentRunner;
    }

    private void DistortionTypeCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
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

        var (minVal, maxVal, unit) = ImageDistortionService.GetValidIntensityRange(selected);
        string rangeHint = string.IsNullOrEmpty(unit)
            ? $"Допустимый диапазон: от {minVal:0} до {maxVal:0}"
            : $"Допустимый диапазон: от {minVal:0} до {maxVal:0} {unit}";
        ExpStartBox.ToolTip = $"Начальное значение интенсивности. {rangeHint}";
        ExpEndBox.ToolTip = $"Конечное значение интенсивности. {rangeHint}";
    }

    private async void StartExperimentSeries_Click(object sender, RoutedEventArgs e)
    {
        if (_experimentRunner is null || _distortionService is null) return;

        var sourceImage = GetSourceQrImage?.Invoke();
        if (sourceImage is null)
        {
            MessageBox.Show("QR-код для проведения экспериментов не найден. Сначала сформируйте QR-код на вкладке создания.", "Внимание", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var distortion = DistortionTypeCombo.SelectedItem as string ?? ImageDistortionService.DistortionOcclusion;

        if (!double.TryParse(ExpStartBox.Text, out double start) ||
            !double.TryParse(ExpEndBox.Text, out double end) ||
            !double.TryParse(ExpStepBox.Text, out double step))
        {
            MessageBox.Show("Проверьте числовые параметры диапазона (От, До, Шаг).", "Ошибка ввода", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (step <= 0)
        {
            MessageBox.Show("Шаг изменения интенсивности должен быть больше 0.", "Ошибка ввода", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (start > end)
        {
            MessageBox.Show("Начальное значение (От) не может превышать конечное (До).", "Ошибка ввода", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var (minVal, maxVal, unit) = ImageDistortionService.GetValidIntensityRange(distortion);
        if (start < minVal || end > maxVal)
        {
            string unitSuffix = string.IsNullOrEmpty(unit) ? string.Empty : $" {unit}";
            MessageBox.Show(
                $"Для искажения «{distortion}» допустимый диапазон интенсивности составляет от {minVal:0} до {maxVal:0}{unitSuffix}.",
                "Недопустимый диапазон",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }

        int attempts = int.TryParse(ExpAttemptsBox.Text, out int a) && a > 0 ? a : 10;
        int seed = int.TryParse(ExpSeedBox.Text, out int s) ? s : 42;

        StartExperimentBtn.Visibility = Visibility.Collapsed;
        ExperimentProgressBar.Visibility = Visibility.Visible;
        ExperimentProgressBar.Value = 0;
        StopExperimentBtn.IsEnabled = true;
        StopExperimentBtn.Visibility = Visibility.Visible;

        _lastExperimentSourceImage = sourceImage;
        _currentDistortedSample = null;
        DistortedSamplePreview.Source = null;
        DistortedSampleCaption.Text = "Выполняется серия экспериментов...";
        _experimentResults.Clear();

        _experimentCts?.Dispose();
        _experimentCts = new CancellationTokenSource();
        var token = _experimentCts.Token;

        try
        {
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

                            if (ExperimentResultsGrid.SelectedItem is null)
                            {
                                ShowDistortedSampleForResult(pointResult);
                            }
                        });
                    },
                    token
                );
            });
        }
        finally
        {
            if (ExperimentResultsGrid.SelectedItem is null && _experimentResults.Count > 0)
            {
                ExperimentResultsGrid.SelectedItem = _experimentResults[^1];
            }
            else if (_experimentResults.Count == 0)
            {
                DistortedSampleCaption.Text = "Эксперимент остановлен до завершения первой точки.";
            }

            StartExperimentBtn.Visibility = Visibility.Visible;
            StartExperimentBtn.IsEnabled = true;
            StopExperimentBtn.Visibility = Visibility.Collapsed;
            StopExperimentBtn.IsEnabled = true;
            ExperimentProgressBar.Visibility = Visibility.Collapsed;

            _experimentCts?.Dispose();
            _experimentCts = null;
        }
    }

    private void StopExperimentSeries_Click(object sender, RoutedEventArgs e)
    {
        if (_experimentCts is null) return;

        StopExperimentBtn.IsEnabled = false;
        _experimentCts.Cancel();
    }

    private void ExperimentResultsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ExperimentResultsGrid.SelectedItem is ExperimentResult selected)
        {
            ShowDistortedSampleForResult(selected);
        }
    }

    private void ShowDistortedSampleForResult(ExperimentResult result)
    {
        if (_distortionService is null) return;

        var sourceImage = _lastExperimentSourceImage ?? GetSourceQrImage?.Invoke();
        if (sourceImage is null) return;

        var sample = _distortionService.Apply(sourceImage, result.Distortion, result.Intensity, result.Seed);
        _currentDistortedSample = sample;
        DistortedSamplePreview.Source = sample;
        DistortedSampleCaption.Text = $"{result.Distortion}: {result.Intensity:F1} (P_decode = {result.DecodeRate:P1})";
    }

    private void SaveDistortedSample_Click(object sender, RoutedEventArgs e)
    {
        if (_qrService is null || _currentDistortedSample is null)
        {
            MessageBox.Show("Сначала запустите серию экспериментов или выберите строку в таблице результатов.", "Внимание", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        string fileName = ExperimentResultsGrid.SelectedItem is ExperimentResult selected
            ? $"distorted_qr_{selected.Intensity:F1}.png"
            : "distorted_qr_sample.png";

        var dialog = new SaveFileDialog
        {
            Title = "Сохранение образца искаженного QR-кода",
            Filter = "Изображение PNG (*.png)|*.png",
            FileName = fileName
        };

        if (dialog.ShowDialog() == true)
        {
            try
            {
                _qrService.SavePng(_currentDistortedSample, dialog.FileName);
                MessageBox.Show($"Образец искажения успешно сохранен:\n{dialog.FileName}", "Файл сохранен", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Не удалось сохранить изображение: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
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
                File.WriteAllText(dialog.FileName, csv, Encoding.UTF8);
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
        _currentDistortedSample = null;
        DistortedSamplePreview.Source = null;
        DistortedSampleCaption.Text = "Выберите строку в таблице результатов для просмотра образца.";
    }
}
