using System.IO;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace QrAuthenticity.Experiments;

/// <summary>
/// Сервис моделирования физических и оптических искажений QR-кода.
/// Применяется в экспериментальном стенде для оценки помехоустойчивости
/// кодов Рида-Соломона (L, M, Q, H) и лавинного эффекта цифровой подписи.
/// </summary>
public sealed class ImageDistortionService
{
    public const string DistortionRotate = "Поворот (градусы)";
    public const string DistortionScale = "Снижение разрешения (%)";
    public const string DistortionOcclusion = "Перекрытие пятном (%)";
    public const string DistortionNoise = "Импульсный шум (%)";
    public const string DistortionBlur = "Размытие (радиус)";
    public const string DistortionContrast = "Снижение контраста (%)";
    public const string DistortionJpeg = "Сжатие JPEG (артефакты)";

    public static IReadOnlyList<string> AvailableDistortions { get; } = new[]
    {
        DistortionRotate,
        DistortionScale,
        DistortionOcclusion,
        DistortionNoise,
        DistortionBlur,
        DistortionContrast,
        DistortionJpeg
    };

    /// <summary>
    /// Применяет выбранное искажение к исходному изображению с заданной интенсивностью.
    /// Исходный объект никогда не модифицируется на месте (создается новая копия).
    /// </summary>
    public BitmapSource Apply(BitmapSource source, string distortion, double intensity, int seed = 42)
    {
        if (intensity <= 0.0001)
            return source;

        return distortion switch
        {
            DistortionRotate => ApplyRotate(source, intensity),
            DistortionScale => ApplyScale(source, intensity),
            DistortionOcclusion => ApplyOcclusion(source, intensity, seed),
            DistortionNoise => ApplySaltPepperNoise(source, intensity, seed),
            DistortionBlur => ApplyBlur(source, intensity),
            DistortionContrast => ApplyContrast(source, intensity),
            DistortionJpeg => ApplyJpegReencode(source, intensity),
            _ => throw new ArgumentException($"Неизвестный тип искажения: {distortion}", nameof(distortion))
        };
    }

    private static BitmapSource ApplyRotate(BitmapSource source, double angleDegrees)
    {
        var (pixels, width, height, stride) = GetPixelBufferBgra32(source);
        var result = new byte[stride * height];

        // Заполняем фон белым цветом (255)
        Array.Fill(result, (byte)255);

        float cx = width / 2f;
        float cy = height / 2f;
        float rad = (float)(-angleDegrees * Math.PI / 180.0);
        float cos = (float)Math.Cos(rad);
        float sin = (float)Math.Sin(rad);

        for (int y = 0; y < height; y++)
        {
            float dy = y - cy;
            for (int x = 0; x < width; x++)
            {
                float dx = x - cx;
                int srcX = (int)Math.Round(cx + dx * cos - dy * sin);
                int srcY = (int)Math.Round(cy + dx * sin + dy * cos);

                int dstIdx = y * stride + x * 4;

                if (srcX >= 0 && srcX < width && srcY >= 0 && srcY < height)
                {
                    int srcIdx = srcY * stride + srcX * 4;
                    result[dstIdx] = pixels[srcIdx];
                    result[dstIdx + 1] = pixels[srcIdx + 1];
                    result[dstIdx + 2] = pixels[srcIdx + 2];
                    result[dstIdx + 3] = 255;
                }
            }
        }

        return CreateBitmapFromPixels(result, width, height, stride);
    }

    private static BitmapSource ApplyScale(BitmapSource source, double intensityPercent)
    {
        var (pixels, width, height, stride) = GetPixelBufferBgra32(source);
        double factor = Math.Clamp(1.0 - (intensityPercent / 100.0), 0.1, 1.0);

        int lowW = Math.Max(8, (int)(width * factor));
        int lowH = Math.Max(8, (int)(height * factor));

        var result = new byte[stride * height];

        for (int y = 0; y < height; y++)
        {
            int sampleY = (int)((double)y / height * lowH);
            int origSampleY = Math.Clamp((int)((double)sampleY / lowH * height), 0, height - 1);

            for (int x = 0; x < width; x++)
            {
                int sampleX = (int)((double)x / width * lowW);
                int origSampleX = Math.Clamp((int)((double)sampleX / lowW * width), 0, width - 1);

                int srcIdx = origSampleY * stride + origSampleX * 4;
                int dstIdx = y * stride + x * 4;

                result[dstIdx] = pixels[srcIdx];
                result[dstIdx + 1] = pixels[srcIdx + 1];
                result[dstIdx + 2] = pixels[srcIdx + 2];
                result[dstIdx + 3] = 255;
            }
        }

        return CreateBitmapFromPixels(result, width, height, stride);
    }

    private static BitmapSource ApplyOcclusion(BitmapSource source, double areaPercent, int seed)
    {
        var (pixels, width, height, stride) = GetPixelBufferBgra32(source);

        double fraction = Math.Clamp(areaPercent / 100.0, 0.0, 0.5);
        int totalPixelsToOcclude = (int)(width * height * fraction);
        int rectWidth = (int)Math.Sqrt(totalPixelsToOcclude * 1.2);
        int rectHeight = totalPixelsToOcclude / Math.Max(1, rectWidth);

        rectWidth = Math.Min(rectWidth, width - 2);
        rectHeight = Math.Min(rectHeight, height - 2);

        var rng = new Random(seed);
        int startX = rng.Next(width / 8, Math.Max(width / 8 + 1, width - rectWidth - width / 8));
        int startY = rng.Next(height / 8, Math.Max(height / 8 + 1, height - rectHeight - height / 8));

        for (int y = startY; y < startY + rectHeight; y++)
        {
            for (int x = startX; x < startX + rectWidth; x++)
            {
                int index = y * stride + x * 4;
                pixels[index] = 0;     // B
                pixels[index + 1] = 0; // G
                pixels[index + 2] = 0; // R
                pixels[index + 3] = 255; // A
            }
        }

        return CreateBitmapFromPixels(pixels, width, height, stride);
    }

    private static BitmapSource ApplySaltPepperNoise(BitmapSource source, double noisePercent, int seed)
    {
        var (pixels, width, height, stride) = GetPixelBufferBgra32(source);
        var rng = new Random(seed);

        double fraction = Math.Clamp(noisePercent / 100.0, 0.0, 0.5);
        int count = (int)(width * height * fraction);

        for (int i = 0; i < count; i++)
        {
            int x = rng.Next(0, width);
            int y = rng.Next(0, height);
            byte color = (byte)(rng.Next(2) == 0 ? 0 : 255);

            int index = y * stride + x * 4;
            pixels[index] = color;
            pixels[index + 1] = color;
            pixels[index + 2] = color;
            pixels[index + 3] = 255;
        }

        return CreateBitmapFromPixels(pixels, width, height, stride);
    }

    private static BitmapSource ApplyBlur(BitmapSource source, double radius)
    {
        var (pixels, width, height, stride) = GetPixelBufferBgra32(source);
        int r = Math.Clamp((int)Math.Round(radius), 1, 12);
        var copy = (byte[])pixels.Clone();

        for (int y = 0; y < height; y++)
        {
            for (int x = 0; x < width; x++)
            {
                int sumB = 0, sumG = 0, sumR = 0, count = 0;

                for (int dy = -r; dy <= r; dy++)
                {
                    int ny = y + dy;
                    if (ny < 0 || ny >= height) continue;

                    for (int dx = -r; dx <= r; dx++)
                    {
                        int nx = x + dx;
                        if (nx < 0 || nx >= width) continue;

                        int idx = ny * stride + nx * 4;
                        sumB += copy[idx];
                        sumG += copy[idx + 1];
                        sumR += copy[idx + 2];
                        count++;
                    }
                }

                int targetIdx = y * stride + x * 4;
                pixels[targetIdx] = (byte)(sumB / count);
                pixels[targetIdx + 1] = (byte)(sumG / count);
                pixels[targetIdx + 2] = (byte)(sumR / count);
                pixels[targetIdx + 3] = 255;
            }
        }

        return CreateBitmapFromPixels(pixels, width, height, stride);
    }

    private static BitmapSource ApplyContrast(BitmapSource source, double reductionPercent)
    {
        var (pixels, width, height, stride) = GetPixelBufferBgra32(source);
        double factor = Math.Clamp(1.0 - (reductionPercent / 100.0), 0.05, 1.0);

        for (int i = 0; i < pixels.Length; i += 4)
        {
            pixels[i] = (byte)Math.Clamp(128 + (pixels[i] - 128) * factor, 0, 255);
            pixels[i + 1] = (byte)Math.Clamp(128 + (pixels[i + 1] - 128) * factor, 0, 255);
            pixels[i + 2] = (byte)Math.Clamp(128 + (pixels[i + 2] - 128) * factor, 0, 255);
        }

        return CreateBitmapFromPixels(pixels, width, height, stride);
    }

    private static BitmapSource ApplyJpegReencode(BitmapSource source, double artifactPercent)
    {
        int quality = (int)Math.Clamp(100 - artifactPercent, 5, 100);
        var encoder = new JpegBitmapEncoder { QualityLevel = quality };
        encoder.Frames.Add(BitmapFrame.Create(source));

        using var ms = new MemoryStream();
        encoder.Save(ms);
        ms.Position = 0;

        var decoder = new JpegBitmapDecoder(ms, BitmapCreateOptions.PreservePixelFormat, BitmapCacheOption.OnLoad);
        var frame = decoder.Frames[0];
        frame.Freeze();
        return frame;
    }

    private static (byte[] Pixels, int Width, int Height, int Stride) GetPixelBufferBgra32(BitmapSource source)
    {
        var converted = new FormatConvertedBitmap(source, PixelFormats.Bgra32, null, 0);
        int width = converted.PixelWidth;
        int height = converted.PixelHeight;
        int stride = width * 4;
        var pixels = new byte[stride * height];
        converted.CopyPixels(pixels, stride, 0);
        return (pixels, width, height, stride);
    }

    private static BitmapSource CreateBitmapFromPixels(byte[] pixels, int width, int height, int stride)
    {
        var bitmap = BitmapSource.Create(width, height, 96, 96, PixelFormats.Bgra32, null, pixels, stride);
        bitmap.Freeze();
        return bitmap;
    }
}
