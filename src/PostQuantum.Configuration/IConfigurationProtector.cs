using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;

namespace PostQuantum.Configuration;

/// <summary>
/// Seals and recovers individual configuration values — connection strings, API keys, whole appsettings
/// sections serialised to a string — as compact, self-describing tokens.
/// </summary>
/// <remarks>
/// <para>
/// Each call to <see cref="ProtectAsync"/> mints a fresh 256-bit content key, encrypts the value with
/// AES-256-GCM, and embeds the wrapped content key in the returned token, so every protected value is an
/// independent envelope. <see cref="UnprotectAsync"/> reverses that with the same key provider.
/// </para>
/// <para>
/// The synchronous <see cref="Protect"/> / <see cref="Unprotect"/> / <see cref="TryUnprotect"/> members
/// exist because the configuration system loads synchronously. They are safe with the in-process local
/// key provider (its work completes synchronously); with a network-backed cloud-KMS provider, prefer the
/// async members and reserve the sync ones for startup paths where blocking is acceptable.
/// </para>
/// </remarks>
public interface IConfigurationProtector
{
    /// <summary>
    /// Seals <paramref name="plaintext"/> and returns a <c>pqc.v1.</c> token safe to store in source
    /// control, appsettings, or any non-secret medium.
    /// </summary>
    /// <param name="plaintext">The sensitive value to protect.</param>
    /// <param name="context">
    /// Optional context bound into the token's authenticated data. When supplied, the same context must
    /// be passed to <see cref="UnprotectAsync"/>; this prevents a token from being moved to a different
    /// logical slot (for example, swapping one configuration key's value onto another).
    /// </param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    Task<string> ProtectAsync(string plaintext, string? context = null, CancellationToken cancellationToken = default);

    /// <summary>Recovers the plaintext from a token produced by <see cref="ProtectAsync"/>.</summary>
    /// <param name="token">The protected token.</param>
    /// <param name="context">The same context, if any, that was supplied to <see cref="ProtectAsync"/>.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <exception cref="ConfigurationProtectionException">
    /// The token is malformed, or the ciphertext/tag/context does not authenticate.
    /// </exception>
    Task<string> UnprotectAsync(string token, string? context = null, CancellationToken cancellationToken = default);

    /// <summary>Synchronous companion to <see cref="ProtectAsync"/>.</summary>
    string Protect(string plaintext, string? context = null);

    /// <summary>Synchronous companion to <see cref="UnprotectAsync"/>.</summary>
    /// <exception cref="ConfigurationProtectionException">
    /// The token is malformed, or the ciphertext/tag/context does not authenticate.
    /// </exception>
    string Unprotect(string token, string? context = null);

    /// <summary>
    /// Attempts to recover the plaintext from <paramref name="token"/>, returning <see langword="false"/>
    /// instead of throwing when the token is missing, malformed, or fails authentication.
    /// </summary>
    bool TryUnprotect(string token, [NotNullWhen(true)] out string? plaintext, string? context = null);

    /// <summary>
    /// Returns <see langword="true"/> if <paramref name="value"/> looks like a protected token (it begins
    /// with the <c>pqc.v1.</c> prefix). A cheap structural check — it does not prove the token decrypts.
    /// </summary>
    static bool IsProtected([NotNullWhen(true)] string? value) => ProtectedValue.HasPrefix(value);
}
