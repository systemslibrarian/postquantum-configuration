using System.Buffers.Binary;
using System.IO;
using PostQuantum.Configuration.Internal;
using Xunit;

namespace PostQuantum.Configuration.Tests;

public sealed class PortableEncodingTests
{
    [Theory]
    [InlineData(new byte[0])]
    [InlineData(new byte[] { 0x00 })]
    [InlineData(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF })]
    public void Base64Url_roundtrips(byte[] data)
    {
        string encoded = PortableEncoding.ToBase64Url(data);
        Assert.DoesNotContain('+', encoded);
        Assert.DoesNotContain('/', encoded);
        Assert.DoesNotContain('=', encoded);
        Assert.Equal(data, PortableEncoding.FromBase64Url(encoded));
    }

    [Fact]
    public void WriteBytes_then_ReadBytes_roundtrips()
    {
        using var stream = new MemoryStream();
        PortableEncoding.WriteByte(stream, 7);
        PortableEncoding.WriteBytes(stream, new byte[] { 1, 2, 3 });
        PortableEncoding.WriteBytes(stream, Array.Empty<byte>());

        byte[] buffer = stream.ToArray();
        int offset = 0;
        Assert.Equal(7, PortableEncoding.ReadByte(buffer, ref offset));
        Assert.Equal(new byte[] { 1, 2, 3 }, PortableEncoding.ReadBytes(buffer, ref offset));
        Assert.Equal(Array.Empty<byte>(), PortableEncoding.ReadBytes(buffer, ref offset));
        Assert.Equal(buffer.Length, offset);
    }

    [Fact]
    public void ReadBytes_rejects_a_length_that_runs_past_the_buffer()
    {
        // Length prefix claims 100 bytes; only 2 follow.
        var buffer = new byte[sizeof(int) + 2];
        BinaryPrimitives.WriteInt32BigEndian(buffer, 100);
        int offset = 0;
        Assert.Throws<FormatException>(() => PortableEncoding.ReadBytes(buffer, ref offset));
    }

    [Fact]
    public void ReadBytes_rejects_a_negative_length()
    {
        var buffer = new byte[sizeof(int) + 4];
        BinaryPrimitives.WriteInt32BigEndian(buffer, -1);
        int offset = 0;
        Assert.Throws<FormatException>(() => PortableEncoding.ReadBytes(buffer, ref offset));
    }

    [Fact]
    public void ReadBytes_rejects_an_oversized_length_without_overflowing_or_allocating()
    {
        // A near-int.MaxValue length prefix must be rejected by the cap, not attempted as an allocation
        // and not silently passed by an offset + length overflow.
        var buffer = new byte[sizeof(int) + 8];
        BinaryPrimitives.WriteInt32BigEndian(buffer, int.MaxValue - 1);
        int offset = 0;
        Assert.Throws<FormatException>(() => PortableEncoding.ReadBytes(buffer, ref offset));
    }

    [Fact]
    public void ReadByte_rejects_an_exhausted_buffer()
    {
        var buffer = Array.Empty<byte>();
        int offset = 0;
        Assert.Throws<FormatException>(() => PortableEncoding.ReadByte(buffer, ref offset));
    }

    [Fact]
    public void FromBase64Url_rejects_an_invalid_length()
    {
        Assert.Throws<FormatException>(() => PortableEncoding.FromBase64Url("A"));
    }
}
