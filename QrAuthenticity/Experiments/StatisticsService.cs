using System.Globalization;
using System.Text;
using QrAuthenticity.Models;

namespace QrAuthenticity.Experiments;

/// <summary>
/// Сервис статистической обработки результатов экспериментов и экспорта в CSV
/// для вставки таблиц и графиков в пояснительную записку.
/// </summary>
public sealed class StatisticsService
{
    public string ToCsv(IEnumerable<ExperimentResult> results)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Искажение,Интенсивность,Попыток,Успешно_распознано,Валидных_подписей,Вероятность_распознавания,Среднее_время_мс");

        foreach (var r in results)
        {
            sb.AppendLine(string.Join(',',
                EscapeCsv(r.Distortion),
                r.Intensity.ToString(CultureInfo.InvariantCulture),
                r.Attempts,
                r.DecodeSuccesses,
                r.ValidSignatures,
                r.DecodeRate.ToString("F4", CultureInfo.InvariantCulture),
                r.AverageDecodeMilliseconds.ToString("F2", CultureInfo.InvariantCulture)
            ));
        }

        return sb.ToString();
    }

    private static string EscapeCsv(string value)
    {
        if (value.Contains(',') || value.Contains('"') || value.Contains('\n'))
        {
            return $"\"{value.Replace("\"", "\"\"")}\"";
        }
        return value;
    }
}
