using System.Security.Cryptography;
using System.Text;

namespace PostQuantum.Configuration;

/// <summary>
/// A recovered secret held as a mutable byte buffer that is zeroed on <see cref="Dispose"/>, instead of
/// an immutable <see cref="string"/> that lingers on the managed heap until garbage collection.
/// </summary>
/// <remarks>
/// <para>
/// Use this when you want to minimise how long decrypted material stays in memory:
/// </para>
/// <code>
/// using Secret secret = protector.UnprotectToSecret(token);
/// UseBytes(secret.Bytes);            // operate on the span directly…
/// // string s = secret.Reveal();    // …or materialise a string only if you must (see Reveal()).
/// </code>
/// <para>
/// <b>This is a mitigation, not a guarantee.</b> The CLR can still copy buffers during GC compaction,
/// and any <see cref="string"/> you create with <see cref="Reveal"/> is outside this type's control.
/// It does, however, remove the unavoidable lingering-<see cref="string"/> footgun for code paths that
/// can work with bytes. Always wrap a <see cref="Secret"/> in a <c>using</c>.
/// </para>
/// </remarks>
public sealed class Secret : IDisposable
{
    private byte[]? _bytes;

    /// <summary>Takes ownership of <paramref name="bytes"/>; the buffer is zeroed when this instance is disposed.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="bytes"/> is <see langword="null"/>.</exception>
    public Secret(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        _bytes = bytes;
    }

    /// <summary>The secret bytes (UTF-8 for values protected from text). Valid until <see cref="Dispose"/>.</summary>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    public ReadOnlySpan<byte> Bytes => _bytes ?? throw new ObjectDisposedException(nameof(Secret));

    /// <summary>The length of the secret in bytes.</summary>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    public int Length => (_bytes ?? throw new ObjectDisposedException(nameof(Secret))).Length;

    /// <summary>
    /// Materialises the secret as a UTF-8 <see cref="string"/>. This deliberately re-introduces the
    /// immutable-<see cref="string"/> limitation this type exists to avoid — call it only at the boundary
    /// where an API forces a <see cref="string"/> on you, and keep the result's lifetime short.
    /// </summary>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    public string Reveal()
    {
        byte[] bytes = _bytes ?? throw new ObjectDisposedException(nameof(Secret));
        return Encoding.UTF8.GetString(bytes);
    }

    /// <summary>Copies the secret bytes into <paramref name="destination"/>.</summary>
    /// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
    /// <exception cref="ArgumentException"><paramref name="destination"/> is too small.</exception>
    public void CopyTo(Span<byte> destination)
    {
        byte[] bytes = _bytes ?? throw new ObjectDisposedException(nameof(Secret));
        bytes.CopyTo(destination);
    }

    /// <summary>Renders a redacted description; never the secret bytes.</summary>
    public override string ToString() =>
        _bytes is null ? "Secret(disposed)" : $"Secret(<{_bytes.Length} bytes>)";

    /// <summary>Zeroes the underlying buffer and marks the instance unusable.</summary>
    public void Dispose()
    {
        if (_bytes is not null)
        {
            CryptographicOperations.ZeroMemory(_bytes);
            _bytes = null;
        }
    }
}
