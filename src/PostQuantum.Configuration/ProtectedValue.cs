using System.IO;
using System.Security.Cryptography;
using System.Text;
using PostQuantum.Configuration.Internal;
using PostQuantum.KeyManagement;

namespace PostQuantum.Configuration;

/// <summary>
/// The parsed, on-the-wire form of a single protected configuration value: the wrapped content key
/// needed to recover the data-encryption key, plus the AES-256-GCM nonce, ciphertext, and tag.
/// </summary>
/// <remarks>
/// <para>
/// A protected value is a self-contained envelope. Each value is sealed with its own fresh 256-bit
/// content key (a data-encryption key, "DEK") under AES-256-GCM; the content key is wrapped by the
/// key-encryption key owned by an <see cref="IContentKeyProvider"/> and travels inside the token. That
/// means any single token can be decrypted with nothing more than the provider — no shared per-process
/// state — which is exactly what configuration and secrets workloads want.
/// </para>
/// <para>
/// The textual token is <c>pqc.v1.&lt;base64url&gt;</c>: a stable, greppable prefix followed by the
/// URL-safe Base64 of a compact, length-prefixed binary body. <see cref="Decode"/> validates every
/// field with overflow-safe arithmetic and a 1&#160;MiB cap (see <see cref="PortableEncoding"/>), so a
/// hostile token cannot trigger a huge allocation or an out-of-bounds read.
/// </para>
/// </remarks>
internal sealed class ProtectedValue
{
    /// <summary>The stable, human-recognisable token prefix. Used to detect protected values cheaply.</summary>
    internal const string TokenPrefix = "pqc.v1.";

    /// <summary>The binary body format version carried inside the token.</summary>
    internal const byte FormatVersion = 1;

    private const int NonceSizeInBytes = 12;
    private const int TagSizeInBytes = 16;
    private const string AadLabel = "PostQuantum.Configuration/v1";

    private readonly WrappedContentKey _wrappedKey;
    private readonly byte[] _nonce;
    private readonly byte[] _ciphertext;
    private readonly byte[] _tag;

    private ProtectedValue(WrappedContentKey wrappedKey, byte[] nonce, byte[] ciphertext, byte[] tag)
    {
        _wrappedKey = wrappedKey;
        _nonce = nonce;
        _ciphertext = ciphertext;
        _tag = tag;
    }

    /// <summary>The wrapped content key required to recover the DEK via <see cref="IContentKeyProvider.UnwrapAsync"/>.</summary>
    internal WrappedContentKey WrappedKey => _wrappedKey;

    /// <summary>The AES-256-GCM ciphertext length in bytes (equal to the plaintext's UTF-8 byte length).</summary>
    internal int CiphertextLength => _ciphertext.Length;

    /// <summary>
    /// Returns <see langword="true"/> if <paramref name="value"/> begins with the protected-value token
    /// prefix. This is a cheap structural check, not a guarantee that the token decrypts.
    /// </summary>
    internal static bool HasPrefix(string? value) =>
        value is not null && value.StartsWith(TokenPrefix, StringComparison.Ordinal);

    /// <summary>
    /// Seals <paramref name="plaintext"/> under <paramref name="contentKey"/> and returns the encoded
    /// token. The <paramref name="context"/>, when supplied, is mixed into the AES-GCM additional
    /// authenticated data so the resulting token can only be unsealed with the same context.
    /// </summary>
    internal static string Seal(ContentKey contentKey, string plaintext, string? context)
    {
        ArgumentNullException.ThrowIfNull(plaintext);

        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSizeInBytes);
        var ciphertext = new byte[plaintextBytes.Length];
        var tag = new byte[TagSizeInBytes];
        byte[] aad = BuildAad(context);

        try
        {
            using var aes = new AesGcm(contentKey.Key, TagSizeInBytes);
            aes.Encrypt(nonce, plaintextBytes, ciphertext, tag, aad);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintextBytes);
        }

        return new ProtectedValue(contentKey.WrappedKey, nonce, ciphertext, tag).Encode();
    }

    /// <summary>
    /// Decrypts this value using the recovered <paramref name="contentKey"/> and returns the plaintext.
    /// </summary>
    /// <exception cref="ConfigurationProtectionException">
    /// The ciphertext, tag, or context does not authenticate — the value was tampered with, the wrong
    /// key was supplied, or the context differs from the one used at seal time.
    /// </exception>
    internal string Decrypt(ContentKey contentKey, string? context)
    {
        byte[] plaintextBytes = DecryptToBytes(contentKey, context);
        try
        {
            return Encoding.UTF8.GetString(plaintextBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintextBytes);
        }
    }

    /// <summary>
    /// Decrypts this value into a freshly allocated byte buffer that the caller owns and is responsible
    /// for zeroing (for example, by handing it to a <see cref="Secret"/>). Avoids materialising a
    /// lingering <see cref="string"/>.
    /// </summary>
    /// <exception cref="ConfigurationProtectionException">The ciphertext/tag/context does not authenticate.</exception>
    internal byte[] DecryptToBytes(ContentKey contentKey, string? context)
    {
        byte[] aad = BuildAad(context);
        var plaintextBytes = new byte[_ciphertext.Length];

        try
        {
            using var aes = new AesGcm(contentKey.Key, TagSizeInBytes);
            aes.Decrypt(_nonce, _ciphertext, _tag, plaintextBytes, aad);
            return plaintextBytes;
        }
        catch (CryptographicException ex)
        {
            // Don't leak a half-filled buffer if authentication failed.
            CryptographicOperations.ZeroMemory(plaintextBytes);
            // Unify "tampered", "wrong key", and "wrong context" into one opaque failure.
            throw new ConfigurationProtectionException(
                "The protected configuration value failed authentication and could not be decrypted.", ex);
        }
    }

    /// <summary>Encodes this value into a <c>pqc.v1.&lt;base64url&gt;</c> token.</summary>
    internal string Encode()
    {
        using var buffer = new MemoryStream();
        PortableEncoding.WriteByte(buffer, FormatVersion);
        PortableEncoding.WriteBytes(buffer, Encoding.UTF8.GetBytes(_wrappedKey.Encode()));
        PortableEncoding.WriteBytes(buffer, _nonce);
        PortableEncoding.WriteBytes(buffer, _ciphertext);
        PortableEncoding.WriteBytes(buffer, _tag);
        return TokenPrefix + PortableEncoding.ToBase64Url(buffer.ToArray());
    }

    /// <summary>Decodes a token produced by <see cref="Encode"/>.</summary>
    /// <exception cref="ConfigurationProtectionException">The token is null, empty, or malformed.</exception>
    internal static ProtectedValue Decode(string token)
    {
        if (!TryDecode(token, out ProtectedValue? value))
        {
            throw new ConfigurationProtectionException("The value is not a well-formed protected configuration token.");
        }

        return value;
    }

    /// <summary>
    /// Attempts to decode a token produced by <see cref="Encode"/>. Returns <see langword="false"/> on
    /// any malformed input without throwing — suitable for values that arrive from untrusted sources.
    /// </summary>
    internal static bool TryDecode(string? token, out ProtectedValue value)
    {
        value = null!;
        if (!HasPrefix(token))
        {
            return false;
        }

        try
        {
            byte[] data = PortableEncoding.FromBase64Url(token!.Substring(TokenPrefix.Length));
            int offset = 0;

            byte version = PortableEncoding.ReadByte(data, ref offset);
            if (version != FormatVersion)
            {
                return false;
            }

            byte[] wrappedKeyBytes = PortableEncoding.ReadBytes(data, ref offset);
            byte[] nonce = PortableEncoding.ReadBytes(data, ref offset);
            byte[] ciphertext = PortableEncoding.ReadBytes(data, ref offset);
            byte[] tag = PortableEncoding.ReadBytes(data, ref offset);

            // No trailing garbage, fixed sizes for nonce/tag, and a decodable wrapped-key token.
            if (offset != data.Length || nonce.Length != NonceSizeInBytes || tag.Length != TagSizeInBytes)
            {
                return false;
            }

            if (!WrappedContentKey.TryDecode(Encoding.UTF8.GetString(wrappedKeyBytes), out WrappedContentKey? wrappedKey))
            {
                return false;
            }

            value = new ProtectedValue(wrappedKey, nonce, ciphertext, tag);
            return true;
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException or DecoderFallbackException)
        {
            return false;
        }
    }

    private static byte[] BuildAad(string? context)
    {
        if (string.IsNullOrEmpty(context))
        {
            return Encoding.UTF8.GetBytes(AadLabel);
        }

        // Domain-separate the label from the context with a NUL so different (label, context) splits
        // can never collide onto the same byte sequence.
        return Encoding.UTF8.GetBytes(AadLabel + "\0" + context);
    }
}
