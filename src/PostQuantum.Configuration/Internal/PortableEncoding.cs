using System.Buffers.Binary;

namespace PostQuantum.Configuration.Internal;

/// <summary>
/// Compact, versioned, big-endian, length-prefixed binary framing for the protected-value token, plus
/// URL-safe Base64 helpers. Mirrors the hostile-input discipline used across the <c>PostQuantum.*</c>
/// family: every read validates bounds with <em>subtraction</em> (<c>length &gt; available</c>) rather
/// than addition (<c>offset + length &gt; total</c>) so an attacker-supplied length prefix can never
/// overflow <see cref="int"/> arithmetic and slip past the bounds check, and every field is capped so a
/// malformed token cannot force a giant allocation.
/// </summary>
internal static class PortableEncoding
{
    /// <summary>Hard upper bound on any single length-prefixed field (1 MiB). Far above any sane value.</summary>
    internal const int MaxFieldLength = 1 * 1024 * 1024;

    /// <summary>Writes a single byte.</summary>
    internal static void WriteByte(Stream destination, byte value) => destination.WriteByte(value);

    /// <summary>Writes a big-endian 4-byte length prefix followed by the bytes.</summary>
    internal static void WriteBytes(Stream destination, ReadOnlySpan<byte> value)
    {
        Span<byte> lengthPrefix = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(lengthPrefix, value.Length);
        destination.Write(lengthPrefix);
        destination.Write(value);
    }

    /// <summary>Reads a single byte, throwing if the buffer is exhausted.</summary>
    internal static byte ReadByte(byte[] data, ref int offset)
    {
        if (offset > data.Length - 1)
        {
            throw new FormatException("Truncated token: expected one more byte.");
        }

        return data[offset++];
    }

    /// <summary>
    /// Reads a length-prefixed byte field, rejecting negative lengths, lengths that would read past the
    /// end of the buffer, and lengths above <paramref name="maxLength"/>. Returns a fresh array so the
    /// caller may retain it independently of <paramref name="data"/>.
    /// </summary>
    internal static byte[] ReadBytes(byte[] data, ref int offset, int maxLength = MaxFieldLength)
    {
        if (offset > data.Length - sizeof(int))
        {
            throw new FormatException("Truncated token: missing length prefix.");
        }

        int length = BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(offset, sizeof(int)));
        offset += sizeof(int);

        // Subtraction form is overflow-safe; offset + length is not.
        if (length < 0 || length > maxLength || length > data.Length - offset)
        {
            throw new FormatException("Token field length is negative, oversized, or runs past the buffer.");
        }

        byte[] result = data.AsSpan(offset, length).ToArray();
        offset += length;
        return result;
    }

    /// <summary>Encodes bytes as unpadded, URL-safe Base64 (RFC 4648 §5).</summary>
    internal static string ToBase64Url(ReadOnlySpan<byte> bytes)
    {
        string base64 = Convert.ToBase64String(bytes);
        return base64.TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    /// <summary>
    /// Decodes an unpadded, URL-safe Base64 string. Throws <see cref="FormatException"/> on invalid input.
    /// </summary>
    internal static byte[] FromBase64Url(string value)
    {
        string base64 = value.Replace('-', '+').Replace('_', '/');
        switch (base64.Length % 4)
        {
            case 2: base64 += "=="; break;
            case 3: base64 += "="; break;
            case 1: throw new FormatException("Invalid Base64Url length.");
        }

        return Convert.FromBase64String(base64);
    }
}
