using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace PostQuantum.Configuration;

/// <summary>
/// Re-seal helpers for key rotation. After the key provider rotates to a new active key-encryption key,
/// existing tokens still <em>open</em> (previous KEKs are retained for unwrapping) but remain
/// <em>wrapped</em> under the old KEK. Re-sealing migrates them to the new active KEK so the old one can
/// eventually be retired.
/// </summary>
public static class ReprotectExtensions
{
    /// <summary>
    /// Decrypts <paramref name="token"/> and re-seals the plaintext under the provider's current active
    /// key, returning a fresh token. A no-op-equivalent (still a brand-new token) for values already on
    /// the active key. Plaintext is handled via a zeroable <see cref="Secret"/> and never materialised as
    /// a lingering <see cref="string"/>.
    /// </summary>
    /// <exception cref="ConfigurationProtectionException">The token is malformed or fails to authenticate.</exception>
    public static string Reprotect(this IConfigurationProtector protector, string token, string? context = null)
    {
        ArgumentNullException.ThrowIfNull(protector);
        using Secret secret = protector.UnprotectToSecret(token, context);
        // Reveal at the boundary because Protect takes a string; the Secret keeps the window minimal.
        return protector.Protect(secret.Reveal(), context);
    }

    /// <summary>
    /// Re-seals every protected (<c>pqc.v1.</c>) value in <paramref name="values"/> in place, leaving
    /// plaintext entries untouched. Returns the number of values re-sealed.
    /// </summary>
    /// <param name="protector">The protector to decrypt and re-seal with.</param>
    /// <param name="values">A mutable map of configuration values (for example, loaded from a store).</param>
    /// <param name="bindKeyAsContext">
    /// When <see langword="true"/>, each value's key is used as its context for both the unwrap and the
    /// re-seal — matching a transparent layer configured with <c>bindKeyAsContext: true</c>.
    /// </param>
    /// <param name="cancellationToken">A token to cancel between entries.</param>
    /// <returns>The count of values that were protected tokens and got re-sealed.</returns>
    public static async Task<int> ReprotectAllAsync(
        this IConfigurationProtector protector,
        IDictionary<string, string?> values,
        bool bindKeyAsContext = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(protector);
        ArgumentNullException.ThrowIfNull(values);

        int resealed = 0;
        foreach (string key in new List<string>(values.Keys))
        {
            cancellationToken.ThrowIfCancellationRequested();

            string? value = values[key];
            if (!IConfigurationProtector.IsProtected(value))
            {
                continue;
            }

            string? context = bindKeyAsContext ? key : null;
            string plaintext = await protector.UnprotectAsync(value, context, cancellationToken).ConfigureAwait(false);
            values[key] = await protector.ProtectAsync(plaintext, context, cancellationToken).ConfigureAwait(false);
            resealed++;
        }

        return resealed;
    }
}
