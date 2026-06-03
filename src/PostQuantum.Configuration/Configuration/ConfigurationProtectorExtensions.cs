using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Configuration;

namespace PostQuantum.Configuration;

/// <summary>
/// Explicit, decrypt-on-read helpers for callers who prefer to decrypt specific values themselves rather
/// than wrap a whole source with the transparent <c>AddEncrypted</c> layer.
/// </summary>
public static class ConfigurationProtectorExtensions
{
    /// <summary>
    /// Reads <paramref name="key"/> from <paramref name="configuration"/> and, if the value is a protected
    /// token, decrypts it. Plaintext values are returned unchanged; a missing key returns
    /// <see langword="null"/>.
    /// </summary>
    /// <exception cref="ConfigurationProtectionException">The value is a protected token that fails to authenticate.</exception>
    public static string? GetDecrypted(
        this IConfiguration configuration,
        string key,
        IConfigurationProtector protector,
        string? context = null)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(protector);

        string? value = configuration[key];
        return protector.DecryptIfProtected(value, context);
    }

    /// <summary>
    /// Returns the decrypted form of <paramref name="value"/> if it is a protected token, or the value
    /// unchanged otherwise. <see langword="null"/> in, <see langword="null"/> out.
    /// </summary>
    /// <exception cref="ConfigurationProtectionException">The value is a protected token that fails to authenticate.</exception>
    [return: NotNullIfNotNull(nameof(value))]
    public static string? DecryptIfProtected(
        this IConfigurationProtector protector,
        string? value,
        string? context = null)
    {
        ArgumentNullException.ThrowIfNull(protector);

        return IConfigurationProtector.IsProtected(value)
            ? protector.Unprotect(value, context)
            : value;
    }
}
