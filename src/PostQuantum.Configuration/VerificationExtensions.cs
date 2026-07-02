using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace PostQuantum.Configuration;

/// <summary>
/// A startup self-test for the protection pipeline. Call it once before the application takes
/// traffic, so a wrong passphrase, a missing keyring, an unavailable KMS, or a platform without the
/// required primitives fails the deployment loudly at boot — not on the first request that happens to
/// touch an encrypted value.
/// </summary>
public static class VerificationExtensions
{
    /// <summary>
    /// Round-trips a random canary value (with a context) through <paramref name="protector"/> and
    /// throws if the result does not match. Success proves the full seal-and-open path works with the
    /// configured key source; it does <em>not</em> prove any particular stored token will open (a
    /// token from a different keyring or passphrase still fails on its own).
    /// </summary>
    /// <remarks>
    /// A wrap-only provider (for example, a hybrid recipient imported from its public key) can seal
    /// but not open, so this check throws for it by design — such a provider cannot serve decryption
    /// traffic. The canary plaintext is random per call and never stored.
    /// </remarks>
    /// <exception cref="ConfigurationProtectionException">
    /// The round trip failed: the recovered value did not match, or the open path failed. The
    /// application should treat this as fatal at startup.
    /// </exception>
    public static async Task VerifyAsync(
        this IConfigurationProtector protector,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(protector);

        string canary = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        const string context = "PostQuantum.Configuration/verify";

        string token = await protector.ProtectAsync(canary, context, cancellationToken).ConfigureAwait(false);
        string recovered = await protector.UnprotectAsync(token, context, cancellationToken).ConfigureAwait(false);

        if (!CryptographicOperations.FixedTimeEquals(
                System.Text.Encoding.UTF8.GetBytes(canary),
                System.Text.Encoding.UTF8.GetBytes(recovered)))
        {
            throw new ConfigurationProtectionException(
                "The protection self-test round trip did not return the original value.");
        }
    }

    /// <summary>Synchronous companion to <see cref="VerifyAsync"/>, for startup paths that cannot await.</summary>
    /// <exception cref="ConfigurationProtectionException">The round trip failed.</exception>
    public static void Verify(this IConfigurationProtector protector) =>
        protector.VerifyAsync().GetAwaiter().GetResult();
}
