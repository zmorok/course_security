using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;

namespace QrAuthenticity.Cryptography;

/// <summary>
/// Собственный симметричный блочный шифр на основе классической сбалансированной сети Фейстеля (Feistel Network).
/// Параметры алгоритма:
/// - Размер блока: 128 бит (16 байт) -> разделение на два 64-битных полублока (L, R).
/// - Количество раундов: 16 раундов.
/// - Ключ: произвольной длины, сводится к 256-битному мастер-ключу через SHA-256.
/// - Раундовые ключи: 16 подключей по 64 бита (K_0 .. K_15).
/// - Раундовая функция F(R, K_i):
///     1. Наложение раундового ключа: T = R XOR K_i.
///     2. Нелинейная замена (Confusion): каждый из 8 байт T заменяется через нелинейный S-box (256 байт).
///     3. Линейное рассеивание (Diffusion): умножение на константу золотого сечения 0x9E3779B97F4A7C15 и побитовые циклические сдвиги.
/// - Режим шифрования: CBC (Cipher Block Chaining) с криптографическим вектором инициализации (IV, 16 байт) и дополнением PKCS#7.
/// </summary>
public sealed class FeistelCipher
{
    public const int BlockSize = 16;
    public const int RoundCount = 16;

    // 8-битный нелинейный S-Box (оптимальная нелинейность и максимальная алгебраическая сложность)
    private static readonly byte[] SBox =
    [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ];

    private readonly ulong[] _roundKeys = new ulong[RoundCount];

    /// <summary>
    /// Инициализирует алгоритм шифрования переданным ключом и рассчитывает раундовые подключи.
    /// </summary>
    public FeistelCipher(byte[] key)
    {
        if (key is null || key.Length == 0)
            throw new ArgumentException("Ключ шифрования не может быть пустым.", nameof(key));

        ExpandKey(key);
    }

    /// <summary>
    /// Процедура расширения ключа (Key Schedule): вычисление шестнадцати 64-битных подключей из мастер-ключа.
    /// </summary>
    private void ExpandKey(byte[] rawKey)
    {
        byte[] masterKey = SHA256.HashData(rawKey);

        byte[] buffer = new byte[masterKey.Length + sizeof(int)];
        Buffer.BlockCopy(masterKey, 0, buffer, 0, masterKey.Length);

        for (int i = 0; i < RoundCount; i++)
        {
            BinaryPrimitives.WriteInt32LittleEndian(buffer.AsSpan(masterKey.Length, sizeof(int)), i);
            byte[] roundHash = SHA256.HashData(buffer);
            _roundKeys[i] = BinaryPrimitives.ReadUInt64LittleEndian(roundHash.AsSpan(0, sizeof(ulong)));
        }
    }

    /// <summary>
    /// Круговая раундовая функция F(R, K_i).
    /// </summary>
    private static ulong RoundFunction(ulong r, ulong roundKey)
    {
        // 1. Наложение раундового подключа
        ulong t = r ^ roundKey;

        // 2. Нелинейная замена каждого байта через S-box (Confusion)
        byte b0 = SBox[(byte)t];
        byte b1 = SBox[(byte)(t >> 8)];
        byte b2 = SBox[(byte)(t >> 16)];
        byte b3 = SBox[(byte)(t >> 24)];
        byte b4 = SBox[(byte)(t >> 32)];
        byte b5 = SBox[(byte)(t >> 40)];
        byte b6 = SBox[(byte)(t >> 48)];
        byte b7 = SBox[(byte)(t >> 56)];

        ulong substituted = (ulong)b0 |
                            ((ulong)b1 << 8) |
                            ((ulong)b2 << 16) |
                            ((ulong)b3 << 24) |
                            ((ulong)b4 << 32) |
                            ((ulong)b5 << 40) |
                            ((ulong)b6 << 48) |
                            ((ulong)b7 << 56);

        // 3. Линейное рассеивание (Diffusion): умножение на константу золотого сечения 0x9E3779B97F4A7C15
        ulong diffused = substituted * 0x9E3779B97F4A7C15UL;

        // 4. Побитовые циклические сдвиги и смешивание
        return BitOperations.RotateLeft(diffused, 23) ^
               BitOperations.RotateRight(diffused, 17) ^
               BitOperations.RotateLeft(diffused, 41);
    }

    /// <summary>
    /// Зашифровывает один 128-битный блок (16 байт) по схеме сети Фейстеля.
    /// </summary>
    public void EncryptBlock(ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (input.Length < BlockSize)
            throw new ArgumentException($"Входной блок должен содержать минимум {BlockSize} байт.", nameof(input));
        if (output.Length < BlockSize)
            throw new ArgumentException($"Выходной буфер должен содержать минимум {BlockSize} байт.", nameof(output));

        ulong l = BinaryPrimitives.ReadUInt64LittleEndian(input[..8]);
        ulong r = BinaryPrimitives.ReadUInt64LittleEndian(input[8..16]);

        for (int i = 0; i < RoundCount; i++)
        {
            ulong nextL = r;
            ulong nextR = l ^ RoundFunction(r, _roundKeys[i]);
            l = nextL;
            r = nextR;
        }

        // Финальная перестановка полублоков (R_16, L_16)
        BinaryPrimitives.WriteUInt64LittleEndian(output[..8], r);
        BinaryPrimitives.WriteUInt64LittleEndian(output[8..16], l);
    }

    /// <summary>
    /// Расшифровывает один 128-битный блок (16 байт) по схеме сети Фейстеля (ключи в обратном порядке).
    /// </summary>
    public void DecryptBlock(ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (input.Length < BlockSize)
            throw new ArgumentException($"Входной блок должен содержать минимум {BlockSize} байт.", nameof(input));
        if (output.Length < BlockSize)
            throw new ArgumentException($"Выходной буфер должен содержать минимум {BlockSize} байт.", nameof(output));

        ulong l = BinaryPrimitives.ReadUInt64LittleEndian(input[..8]);
        ulong r = BinaryPrimitives.ReadUInt64LittleEndian(input[8..16]);

        for (int i = RoundCount - 1; i >= 0; i--)
        {
            ulong nextL = r;
            ulong nextR = l ^ RoundFunction(r, _roundKeys[i]);
            l = nextL;
            r = nextR;
        }

        // Финальная перестановка восстанавливает исходный (L_0, R_0)
        BinaryPrimitives.WriteUInt64LittleEndian(output[..8], r);
        BinaryPrimitives.WriteUInt64LittleEndian(output[8..16], l);
    }

    /// <summary>
    /// Зашифровывает массив байт произвольной длины в режиме CBC (Cipher Block Chaining)
    /// со случайным вектором инициализации (IV) и выравниванием PKCS#7.
    /// </summary>
    public byte[] EncryptCbc(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> iv)
    {
        if (iv.Length != BlockSize)
            throw new ArgumentException($"Вектор инициализации (IV) должен быть длиной ровно {BlockSize} байт.", nameof(iv));

        int padLen = BlockSize - (plaintext.Length % BlockSize);
        int totalLen = plaintext.Length + padLen;
        byte[] padded = new byte[totalLen];
        plaintext.CopyTo(padded);
        for (int i = plaintext.Length; i < totalLen; i++)
        {
            padded[i] = (byte)padLen;
        }

        byte[] ciphertext = new byte[totalLen];
        Span<byte> prevBlock = stackalloc byte[BlockSize];
        iv.CopyTo(prevBlock);

        Span<byte> blockIn = stackalloc byte[BlockSize];
        for (int offset = 0; offset < totalLen; offset += BlockSize)
        {
            for (int b = 0; b < BlockSize; b++)
            {
                blockIn[b] = (byte)(padded[offset + b] ^ prevBlock[b]);
            }

            EncryptBlock(blockIn, ciphertext.AsSpan(offset, BlockSize));
            ciphertext.AsSpan(offset, BlockSize).CopyTo(prevBlock);
        }

        return ciphertext;
    }

    /// <summary>
    /// Расшифровывает данные в режиме CBC, снимает и валидирует дополнение PKCS#7.
    /// </summary>
    public byte[] DecryptCbc(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> iv)
    {
        if (iv.Length != BlockSize)
            throw new ArgumentException($"Вектор инициализации (IV) должен быть длиной ровно {BlockSize} байт.", nameof(iv));
        if (ciphertext.Length == 0 || ciphertext.Length % BlockSize != 0)
            throw new CryptographicException("Длина шифротекста должна быть ненулевой и кратной 16 байтам.");

        byte[] plaintext = new byte[ciphertext.Length];
        Span<byte> prevBlock = stackalloc byte[BlockSize];
        iv.CopyTo(prevBlock);

        Span<byte> blockOut = stackalloc byte[BlockSize];
        for (int offset = 0; offset < ciphertext.Length; offset += BlockSize)
        {
            DecryptBlock(ciphertext.Slice(offset, BlockSize), blockOut);
            for (int b = 0; b < BlockSize; b++)
            {
                plaintext[offset + b] = (byte)(blockOut[b] ^ prevBlock[b]);
            }

            ciphertext.Slice(offset, BlockSize).CopyTo(prevBlock);
        }

        // Проверка и удаление дополнения PKCS#7
        int padLen = plaintext[^1];
        if (padLen < 1 || padLen > BlockSize || padLen > plaintext.Length)
            throw new CryptographicException("Неверное дополнение PKCS#7: недопустимое значение длины заполнения.");

        for (int i = plaintext.Length - padLen; i < plaintext.Length; i++)
        {
            if (plaintext[i] != padLen)
                throw new CryptographicException("Неверное дополнение PKCS#7: байты выравнивания повреждены.");
        }

        byte[] result = new byte[plaintext.Length - padLen];
        Array.Copy(plaintext, result, result.Length);
        return result;
    }
}
