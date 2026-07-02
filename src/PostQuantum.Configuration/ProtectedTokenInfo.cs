using System.Diagnostics.CodeAnalysis;

namespace PostQuantum.Configuration;

/// <summary>
/// Non-secret metadata read from a protected (<c>pqc.v1.</c>) token <em>without</em> any key material:
/// the envelope format version, which provider and key-encryption key wrapped the content key, the
/// wrapping algorithm, and the ciphertext length.
/// </summary>
/// <remarks>
/// <para>
/// Inspection is a structural parse only. A token that inspects successfully is <em>well-formed</em>,
/// not <em>authentic</em> — a tampered token whose framing is intact still inspects. Only decryption
/// with the right key proves integrity; use <see cref="IConfigurationProtector.TryUnprotect"/> for that.
/// </para>
/// <para>
/// The intended uses are operational: confirming a value really is a protected token, and — via
/// <see cref="KeyId"/> — finding tokens still wrapped under a retired key-encryption key after a
/// rotation, so they can be re-sealed (<c>Reprotect</c> / <c>ReprotectAllAsync</c> / the
/// <c>pqc-config reprotect-file</c> command).
/// </para>
/// <para>
/// Nothing here reveals more than the token itself already does: <see cref="CiphertextLength"/> equals
/// the plaintext's UTF-8 byte length (AES-GCM does not pad), but that is already derivable from the
/// token's own length. No plaintext and no key material are ever touched.
/// </para>
/// </remarks>
public sealed class ProtectedTokenInfo
{
    private ProtectedTokenInfo(int formatVersion, string providerId, string keyId, string wrapAlgorithm, int ciphertextLength)
    {
        FormatVersion = formatVersion;
        ProviderId = providerId;
        KeyId = keyId;
        WrapAlgorithm = wrapAlgorithm;
        CiphertextLength = ciphertextLength;
    }

    /// <summary>The binary body format version carried inside the token (currently <c>1</c>).</summary>
    public int FormatVersion { get; }

    /// <summary>The identifier of the key provider that wrapped the content key (for example, <c>"local.v1"</c>).</summary>
    public string ProviderId { get; }

    /// <summary>
    /// The identifier of the key-encryption key that wrapped this token's content key. After a key
    /// rotation, tokens whose <see cref="KeyId"/> is not the provider's active key are candidates for
    /// re-sealing.
    /// </summary>
    public string KeyId { get; }

    /// <summary>A human-readable label for the key-wrapping algorithm (for example, <c>"AES-256-GCM"</c>).</summary>
    public string WrapAlgorithm { get; }

    /// <summary>
    /// The AES-256-GCM ciphertext length in bytes — equal to the plaintext's UTF-8 byte length, which
    /// the token's overall length already reveals.
    /// </summary>
    public int CiphertextLength { get; }

    /// <summary>
    /// Attempts to parse the non-secret metadata from <paramref name="token"/>. Returns
    /// <see langword="false"/> on any input that is not a well-formed <c>pqc.v1.</c> token, without
    /// throwing — safe for untrusted input.
    /// </summary>
    /// <param name="token">The value to inspect.</param>
    /// <param name="info">The parsed metadata when the token is well-formed.</param>
    public static bool TryInspect(string? token, [NotNullWhen(true)] out ProtectedTokenInfo? info)
    {
        info = null;
        if (!ProtectedValue.TryDecode(token, out ProtectedValue value))
        {
            return false;
        }

        info = new ProtectedTokenInfo(
            ProtectedValue.FormatVersion,
            value.WrappedKey.ProviderId,
            value.WrappedKey.KeyId,
            value.WrappedKey.Algorithm,
            value.CiphertextLength);
        return true;
    }
}
