using System.IO;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using ZXing;
using ZXing.Common;
using ZXing.QrCode;
using ZXing.QrCode.Internal;

namespace QrAuthenticity.QR;

/// <summary>
/// Сервис генерации, декодирования и сохранения графических изображений QR-кода.
/// Не содержит криптографической логики и отвечает исключительно за оптический контейнер.
/// </summary>
public sealed class QrCodeService
{
    /// <summary>
    /// Формирует растровое изображение QR-кода из текстовой строки с заданным уровнем коррекции ошибок Рида-Соломона.
    /// </summary>
    public BitmapSource Generate(string text, int pixels = 640, ErrorCorrectionLevel? level = null)
    {
        level ??= ErrorCorrectionLevel.M;
        var writer = new QRCodeWriter();
        var hints = new Dictionary<EncodeHintType, object>
        {
            [EncodeHintType.ERROR_CORRECTION] = level,
            [EncodeHintType.MARGIN] = 4,
            [EncodeHintType.CHARACTER_SET] = "UTF-8"
        };

        var matrix = writer.encode(text, BarcodeFormat.QR_CODE, pixels, pixels, hints);
        int stride = matrix.Width * 4;
        var buffer = new byte[stride * matrix.Height];

        for (int y = 0; y < matrix.Height; y++)
        {
            for (int x = 0; x < matrix.Width; x++)
            {
                byte v = matrix[x, y] ? (byte)0 : (byte)255;
                int i = y * stride + x * 4;
                buffer[i] = v;       // B
                buffer[i + 1] = v;   // G
                buffer[i + 2] = v;   // R
                buffer[i + 3] = 255; // A
            }
        }

        var image = BitmapSource.Create(
            matrix.Width,
            matrix.Height,
            96,
            96,
            PixelFormats.Bgra32,
            null,
            buffer,
            stride
        );

        image.Freeze();
        return image;
    }

    /// <summary>
    /// Распознает и извлекает текстовую полезную нагрузку из изображения QR-кода.
    /// Возвращает null в случае, если код не найден или повреждения превысили предел кодов Рида-Соломона.
    /// </summary>
    public string? Decode(BitmapSource source)
    {
        var text = TryDecodeInternal(source);
        if (text is not null) return text;

        // Попытка восстановления: добавление белой защитной зоны (Quiet Zone)
        // на случай, если изображение было обрезано вплотную к матрице
        try
        {
            var padded = AddQuietZone(source, 24);
            return TryDecodeInternal(padded);
        }
        catch
        {
            return null;
        }
    }

    private string? TryDecodeInternal(BitmapSource source)
    {
        var converted = new FormatConvertedBitmap(source, PixelFormats.Bgr24, null, 0);
        int stride = (converted.PixelWidth * converted.Format.BitsPerPixel + 7) / 8;
        var pixels = new byte[stride * converted.PixelHeight];
        converted.CopyPixels(pixels, stride, 0);

        var luminance = new RGBLuminanceSource(pixels, converted.PixelWidth, converted.PixelHeight, RGBLuminanceSource.BitmapFormat.BGR24);
        var reader = new QRCodeReader();

        // 1. Стандартный детектор с поиском угловых меток (для фото, поворотов, искажений)
        var hintsDetector = new Dictionary<DecodeHintType, object>
        {
            [DecodeHintType.TRY_HARDER] = true,
            [DecodeHintType.CHARACTER_SET] = "UTF-8"
        };

        try
        {
            var bitmap = new BinaryBitmap(new HybridBinarizer(luminance));
            var res = reader.decode(bitmap, hintsDetector);
            if (res is not null && !string.IsNullOrEmpty(res.Text)) return res.Text;
        }
        catch { }

        try
        {
            var bitmap = new BinaryBitmap(new GlobalHistogramBinarizer(luminance));
            var res = reader.decode(bitmap, hintsDetector);
            if (res is not null && !string.IsNullOrEmpty(res.Text)) return res.Text;
        }
        catch { }

        // 2. Режим PURE_BARCODE (для чистых цифровых изображений высокой плотности)
        var hintsPure = new Dictionary<DecodeHintType, object>
        {
            [DecodeHintType.PURE_BARCODE] = true,
            [DecodeHintType.CHARACTER_SET] = "UTF-8"
        };

        try
        {
            var bitmap = new BinaryBitmap(new HybridBinarizer(luminance));
            var res = reader.decode(bitmap, hintsPure);
            if (res is not null && !string.IsNullOrEmpty(res.Text)) return res.Text;
        }
        catch { }

        try
        {
            var bitmap = new BinaryBitmap(new GlobalHistogramBinarizer(luminance));
            var res = reader.decode(bitmap, hintsPure);
            if (res is not null && !string.IsNullOrEmpty(res.Text)) return res.Text;
        }
        catch { }

        return null;
    }

    private static BitmapSource AddQuietZone(BitmapSource source, int margin)
    {
        var converted = new FormatConvertedBitmap(source, PixelFormats.Bgra32, null, 0);
        int srcW = converted.PixelWidth;
        int srcH = converted.PixelHeight;
        int srcStride = srcW * 4;
        var srcPixels = new byte[srcStride * srcH];
        converted.CopyPixels(srcPixels, srcStride, 0);

        int dstW = srcW + margin * 2;
        int dstH = srcH + margin * 2;
        int dstStride = dstW * 4;
        var dstPixels = new byte[dstStride * dstH];
        Array.Fill(dstPixels, (byte)255);

        for (int y = 0; y < srcH; y++)
        {
            int srcOffset = y * srcStride;
            int dstOffset = (y + margin) * dstStride + margin * 4;
            Buffer.BlockCopy(srcPixels, srcOffset, dstPixels, dstOffset, srcStride);
        }

        var padded = BitmapSource.Create(dstW, dstH, 96, 96, PixelFormats.Bgra32, null, dstPixels, dstStride);
        padded.Freeze();
        return padded;
    }

    /// <summary>
    /// Загружает изображение QR-кода из графического файла.
    /// </summary>
    public BitmapSource Load(string path)
    {
        using var stream = File.OpenRead(path);
        var decoder = BitmapDecoder.Create(stream, BitmapCreateOptions.PreservePixelFormat, BitmapCacheOption.OnLoad);
        var frame = decoder.Frames[0];
        frame.Freeze();
        return frame;
    }

    /// <summary>
    /// Сохраняет сформированный QR-код в формате PNG.
    /// </summary>
    public void SavePng(BitmapSource source, string path)
    {
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(source));
        using var stream = File.Create(path);
        encoder.Save(stream);
    }
}
