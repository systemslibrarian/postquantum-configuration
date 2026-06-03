using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using PostQuantum.KeyManagement;

namespace PostQuantum.Configuration;

/// <summary>
/// The default <see cref="IConfigurationProtector"/>. Seals each value with a fresh content key from an
/// <see cref="IContentKeyProvider"/> and AES-256-GCM, producing a self-contained <c>pqc.v1.</c> token.
/// </summary>
/// <remarks>
/// <para>
/// This type is a thin, stateless adapter over <see cref="IContentKeyProvider"/> — all key custody,
/// rotation, and persistence live in <c>PostQuantum.KeyManagement</c>. Register the provider once (for
/// example via <c>AddPostQuantumKeyManagement</c>) and resolve <see cref="IConfigurationProtector"/>
/// wherever you protect or read configuration. It is safe for concurrent use to the same degree the
/// underlying provider is (the local provider is fully thread-safe).
/// </para>
/// <para>
/// The synchronous members (<see cref="Protect"/>, <see cref="Unprotect"/>, <see cref="UnprotectToSecret"/>,
/// <see cref="TryUnprotect"/>) block on the key provider via <c>GetAwaiter().GetResult()</c>. This is safe
/// for an <see cref="IContentKeyProvider"/> that completes synchronously, such as the local keyring
/// provider. If you supply a provider that performs genuine asynchronous I/O (a remote KMS, say), call the
/// <see cref="ProtectAsync"/>/<see cref="UnprotectAsync"/> members instead — blocking on a real async call
/// can starve the thread pool, and will deadlock under a single-threaded synchronization context.
/// </para>
/// <para>
/// Recovered plaintext is returned as a <see cref="string"/>. .NET strings are immutable and cannot be
/// reliably zeroed, so a decrypted secret may linger in the managed heap until garbage collected — an
/// inherent limit of any string-returning API. The intermediate plaintext byte buffers used during
/// encrypt and decrypt are zeroed; see <c>KNOWN-GAPS.md</c> for the full discussion.
/// </para>
/// </remarks>
public sealed class PostQuantumConfigProtector : IConfigurationProtector
{
    private readonly IContentKeyProvider _keyProvider;

    /// <summary>Creates a protector backed by <paramref name="keyProvider"/>.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="keyProvider"/> is <see langword="null"/>.</exception>
    public PostQuantumConfigProtector(IContentKeyProvider keyProvider)
    {
        ArgumentNullException.ThrowIfNull(keyProvider);
        _keyProvider = keyProvider;
    }

    /// <inheritdoc />
    public async Task<string> ProtectAsync(string plaintext, string? context = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        using ContentKey contentKey = await _keyProvider.CreateContentKeyAsync(cancellationToken).ConfigureAwait(false);
        return ProtectedValue.Seal(contentKey, plaintext, context);
    }

    /// <inheritdoc />
    public async Task<string> UnprotectAsync(string token, string? context = null, CancellationToken cancellationToken = default)
    {
        ProtectedValue value = ProtectedValue.Decode(token);
        using ContentKey contentKey = await UnwrapAsync(value, cancellationToken).ConfigureAwait(false);
        return value.Decrypt(contentKey, context);
    }

    /// <inheritdoc />
    public string Protect(string plaintext, string? context = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        // The local provider completes synchronously; AsTask().GetAwaiter().GetResult() avoids the
        // ValueTask "consumed twice" hazard while keeping the sync entry point usable at startup.
        using ContentKey contentKey = _keyProvider.CreateContentKeyAsync(CancellationToken.None).AsTask().GetAwaiter().GetResult();
        return ProtectedValue.Seal(contentKey, plaintext, context);
    }

    /// <inheritdoc />
    public string Unprotect(string token, string? context = null)
    {
        ProtectedValue value = ProtectedValue.Decode(token);
        using ContentKey contentKey = UnwrapAsync(value, CancellationToken.None).AsTask().GetAwaiter().GetResult();
        return value.Decrypt(contentKey, context);
    }

    /// <inheritdoc />
    public Secret UnprotectToSecret(string token, string? context = null)
    {
        ProtectedValue value = ProtectedValue.Decode(token);
        using ContentKey contentKey = UnwrapAsync(value, CancellationToken.None).AsTask().GetAwaiter().GetResult();
        return new Secret(value.DecryptToBytes(contentKey, context));
    }

    /// <inheritdoc />
    public bool TryUnprotect(string token, [NotNullWhen(true)] out string? plaintext, string? context = null)
    {
        plaintext = null;
        if (!ProtectedValue.TryDecode(token, out ProtectedValue? value))
        {
            return false;
        }

        try
        {
            using ContentKey contentKey = UnwrapAsync(value, CancellationToken.None).AsTask().GetAwaiter().GetResult();
            plaintext = value.Decrypt(contentKey, context);
            return true;
        }
        catch (Exception ex) when (ex
            is ConfigurationProtectionException             // malformed token / failed authentication
            or KeyNotFoundException                          // token references a KEK this provider doesn't hold
            or InvalidOperationException                     // wrong provider family, etc.
            or System.Security.Cryptography.CryptographicException)
        {
            // Tampered ciphertext, wrong key/provider, or context mismatch — all reported as a plain
            // "could not unprotect" so the caller never has to distinguish failure modes.
            plaintext = null;
            return false;
        }
    }

    private ValueTask<ContentKey> UnwrapAsync(ProtectedValue value, CancellationToken cancellationToken) =>
        _keyProvider.UnwrapAsync(value.WrappedKey, cancellationToken);
}
