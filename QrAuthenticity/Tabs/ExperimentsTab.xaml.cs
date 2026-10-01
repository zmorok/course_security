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

        int attempts = int.TryParse(ExpAttemptsBox.Text, out int a) && a > 0 ? a : 10;
        int seed = int.TryParse(ExpSeedBox.Text, out int s) ? s : 42;

        StartExperimentBtn.IsEnabled = false;
        ExperimentProgressBar.Visibility = Visibility.Visible;
        ExperimentProgressBar.Value = 0;

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

                        var sample = _distortionService.Apply(sourceImage, distortion, pointResult.Intensity, seed);
                        DistortedSamplePreview.Source = sample;
                    });
                }
            );
        });

        StartExperimentBtn.IsEnabled = true;
        ExperimentProgressBar.Visibility = Visibility.Collapsed;
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
        DistortedSamplePreview.Source = null;
    }
}
