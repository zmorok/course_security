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
    /// Возвращает допустимый физический диапазон интенсивности (Min, Max, единица измерения) для заданного вида искажения.
    /// </summary>
    public static (double Min, double Max, string Unit) GetValidIntensityRange(string distortion) => distortion switch
    {
        DistortionRotate => (0.0, 360.0, "°"),
        DistortionScale => (0.0, 100.0, "%"),
        DistortionOcclusion => (0.0, 100.0, "%"),
        DistortionNoise => (0.0, 100.0, "%"),
        DistortionBlur => (0.0, 100.0, "px"),
        DistortionContrast => (0.0, 100.0, "%"),
        DistortionJpeg => (0.0, 100.0, "%"),
        _ => (0.0, 100.0, string.Empty)
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
        double clamped = Math.Clamp(intensityPercent, 0.0, 100.0);

        int lowW = Math.Clamp((int)Math.Round(width - (width - 1) * (clamped / 100.0)), 1, width);
        int lowH = Math.Clamp((int)Math.Round(height - (height - 1) * (clamped / 100.0)), 1, height);

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

        double fraction = Math.Clamp(areaPercent / 100.0, 0.0, 1.0);
        if (fraction >= 1.0)
        {
            for (int i = 0; i < pixels.Length; i += 4)
            {
                pixels[i] = 0;
                pixels[i + 1] = 0;
                pixels[i + 2] = 0;
                pixels[i + 3] = 255;
            }
            return CreateBitmapFromPixels(pixels, width, height, stride);
        }

        int totalPixelsToOcclude = Math.Max(1, (int)Math.Round(width * height * fraction));
        int rectWidth = Math.Clamp((int)Math.Round(Math.Sqrt(totalPixelsToOcclude * 1.2)), 1, width);
        int rectHeight = Math.Clamp((int)Math.Ceiling((double)totalPixelsToOcclude / rectWidth), 1, height);

        var rng = new Random(seed);
        int maxMarginX = Math.Max(0, (width - rectWidth) / 2);
        int marginX = Math.Min(width / 8, maxMarginX);
        int maxMarginY = Math.Max(0, (height - rectHeight) / 2);
        int marginY = Math.Min(height / 8, maxMarginY);

        int startX = rng.Next(marginX, Math.Max(marginX, width - rectWidth - marginX) + 1);
        int startY = rng.Next(marginY, Math.Max(marginY, height - rectHeight - marginY) + 1);

        int endY = Math.Min(height, startY + rectHeight);
        int endX = Math.Min(width, startX + rectWidth);
        for (int y = startY; y < endY; y++)
        {
            for (int x = startX; x < endX; x++)
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

        double probability = Math.Clamp(noisePercent / 100.0, 0.0, 1.0);
        for (int y = 0; y < height; y++)
        {
            for (int x = 0; x < width; x++)
            {
                if (rng.NextDouble() < probability)
                {
                    byte color = (byte)(rng.Next(2) == 0 ? 0 : 255);
                    int index = y * stride + x * 4;
                    pixels[index] = color;
                    pixels[index + 1] = color;
                    pixels[index + 2] = color;
                    pixels[index + 3] = 255;
                }
            }
        }

        return CreateBitmapFromPixels(pixels, width, height, stride);
    }

    private static BitmapSource ApplyBlur(BitmapSource source, double radius)
    {
        var (pixels, width, height, stride) = GetPixelBufferBgra32(source);
        int r = Math.Clamp((int)Math.Round(radius), 1, Math.Max(width, height));

        int totalPixels = width * height;
        var horizB = new int[totalPixels];
        var horizG = new int[totalPixels];
        var horizR = new int[totalPixels];
        var horizCount = new int[width];

        for (int x = 0; x < width; x++)
        {
            int left = Math.Max(0, x - r);
            int right = Math.Min(width - 1, x + r);
            horizCount[x] = right - left + 1;
        }

        // Горизонтальное скользящее окно O(W * H)
        for (int y = 0; y < height; y++)
        {
            int rowBase = y * width;
            int sumB = 0, sumG = 0, sumR = 0;
            int initRight = Math.Min(width - 1, r);
            for (int x = 0; x <= initRight; x++)
            {
                int idx = y * stride + x * 4;
                sumB += pixels[idx];
                sumG += pixels[idx + 1];
                sumR += pixels[idx + 2];
            }

            for (int x = 0; x < width; x++)
            {
                if (x > 0)
                {
                    int addX = x + r;
                    if (addX < width)
                    {
                        int addIdx = y * stride + addX * 4;
                        sumB += pixels[addIdx];
                        sumG += pixels[addIdx + 1];
                        sumR += pixels[addIdx + 2];
                    }

                    int remX = x - r - 1;
                    if (remX >= 0)
                    {
                        int remIdx = y * stride + remX * 4;
                        sumB -= pixels[remIdx];
                        sumG -= pixels[remIdx + 1];
                        sumR -= pixels[remIdx + 2];
                    }
                }

                horizB[rowBase + x] = sumB;
                horizG[rowBase + x] = sumG;
                horizR[rowBase + x] = sumR;
            }
        }

        // Вертикальное скользящее окно O(W * H)
        for (int x = 0; x < width; x++)
        {
            long sumB = 0, sumG = 0, sumR = 0;
            int initBottom = Math.Min(height - 1, r);
            for (int y = 0; y <= initBottom; y++)
            {
                int pos = y * width + x;
                sumB += horizB[pos];
                sumG += horizG[pos];
                sumR += horizR[pos];
            }

            int hCount = horizCount[x];
            for (int y = 0; y < height; y++)
            {
                if (y > 0)
                {
                    int addY = y + r;
                    if (addY < height)
                    {
                        int addPos = addY * width + x;
                        sumB += horizB[addPos];
                        sumG += horizG[addPos];
                        sumR += horizR[addPos];
                    }

                    int remY = y - r - 1;
                    if (remY >= 0)
                    {
                        int remPos = remY * width + x;
                        sumB -= horizB[remPos];
                        sumG -= horizG[remPos];
                        sumR -= horizR[remPos];
                    }
                }

                int top = Math.Max(0, y - r);
                int bottom = Math.Min(height - 1, y + r);
                int count = hCount * (bottom - top + 1);

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
        double factor = Math.Clamp(1.0 - (reductionPercent / 100.0), 0.0, 1.0);

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
        double clamped = Math.Clamp(artifactPercent, 0.0, 100.0);
        int quality = (int)Math.Clamp(Math.Round(100.0 - clamped), 1, 100);

        int origW = source.PixelWidth;
        int origH = source.PixelHeight;
        BitmapSource toEncode = source;

        if (clamped > 30.0)
        {
            double downscaleFactor = Math.Max(0.06, 1.0 - ((clamped - 30.0) / 70.0) * 0.94);
            int lowW = Math.Clamp((int)Math.Round(origW * downscaleFactor), 8, origW);
            int lowH = Math.Clamp((int)Math.Round(origH * downscaleFactor), 8, origH);

            if (lowW < origW || lowH < origH)
            {
                toEncode = ResizeNearest(source, lowW, lowH);
            }
        }

        var encoder = new JpegBitmapEncoder { QualityLevel = quality };
        encoder.Frames.Add(BitmapFrame.Create(toEncode));

        using var ms = new MemoryStream();
        encoder.Save(ms);
        ms.Position = 0;

        var decoder = new JpegBitmapDecoder(ms, BitmapCreateOptions.PreservePixelFormat, BitmapCacheOption.OnLoad);
        var frame = decoder.Frames[0];

        if (frame.PixelWidth == origW && frame.PixelHeight == origH)
        {
            frame.Freeze();
            return frame;
        }

        return ResizeNearest(frame, origW, origH);
    }

    private static BitmapSource ResizeNearest(BitmapSource source, int targetW, int targetH)
    {
        var (srcPixels, srcW, srcH, srcStride) = GetPixelBufferBgra32(source);
        int outStride = targetW * 4;
        var outPixels = new byte[outStride * targetH];

        for (int y = 0; y < targetH; y++)
        {
            int sy = Math.Clamp((int)((double)y / targetH * srcH), 0, srcH - 1);
            for (int x = 0; x < targetW; x++)
            {
                int sx = Math.Clamp((int)((double)x / targetW * srcW), 0, srcW - 1);
                int srcIdx = sy * srcStride + sx * 4;
                int dstIdx = y * outStride + x * 4;
                outPixels[dstIdx] = srcPixels[srcIdx];
                outPixels[dstIdx + 1] = srcPixels[srcIdx + 1];
                outPixels[dstIdx + 2] = srcPixels[srcIdx + 2];
                outPixels[dstIdx + 3] = 255;
            }
        }

        return CreateBitmapFromPixels(outPixels, targetW, targetH, outStride);
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
