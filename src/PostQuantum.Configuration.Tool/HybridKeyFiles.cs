using PostQuantum.KeyManagement;

namespace PostQuantum.Configuration.Tool;

/// <summary>
/// Reads and writes hybrid (ML-KEM-768 + ECDH P-256) recipient key files for the <c>keygen</c> /
/// <c>--recipient</c> / <c>--to-recipient</c> options. Key files are single-line, prefixed, Base64
/// text — self-describing, so passing the wrong file (or a truncated one) is a clear error, and a
/// public key can never be mistaken for a private one.
/// </summary>
/// <remarks>
/// The hybrid provider needs .NET 10+ (<c>System.Security.Cryptography.MLKem</c>). On older runtimes
/// these helpers exist but fail with a clear, actionable error instead of a missing-command surprise.
/// </remarks>
internal static class HybridKeyFiles
{
    /// <summary>Prefix for the recipient's public (wrap-only) key file — safe to distribute.</summary>
    internal const string PublicPrefix = "pqc.hybrid.pub.v1.";

    /// <summary>Prefix for the recipient's private key file — highly sensitive, never commit it.</summary>
    internal const string PrivatePrefix = "pqc.hybrid.key.v1.";

#if NET10_0_OR_GREATER
    /// <summary>
    /// Generates a fresh recipient key pair and writes both key files. Refuses to overwrite either
    /// path — replacing key material must always be an explicit, manual act.
    /// </summary>
    /// <returns>The recipient's key id (public-key fingerprint, <c>hk-…</c>).</returns>
    /// <exception cref="CliError">A target file already exists.</exception>
    /// <exception cref="PlatformNotSupportedException">ML-KEM is not available on this host.</exception>
    internal static string GenerateAndWrite(string publicPath, string privatePath)
    {
        ThrowIfExists(publicPath);
        ThrowIfExists(privatePath);

        using var provider = Hybrid.HybridKemContentKeyProvider.Generate();
        File.WriteAllText(publicPath, PublicPrefix + Convert.ToBase64String(provider.ExportPublicKey()) + Environment.NewLine);
        File.WriteAllText(privatePath, PrivatePrefix + Convert.ToBase64String(provider.ExportPrivateKey()) + Environment.NewLine);
        return provider.ActiveKeyId;
    }

    /// <summary>
    /// Loads a recipient key file written by <c>keygen</c>. A public key file yields a wrap-only
    /// provider; when <paramref name="needUnwrap"/> is set, only a private key file is accepted.
    /// </summary>
    /// <exception cref="CliError">
    /// The file is missing, is not a recognisable key file, or is a public key where decryption is
    /// required.
    /// </exception>
    /// <exception cref="PlatformNotSupportedException">ML-KEM is not available on this host.</exception>
    internal static IContentKeyProvider Load(string path, bool needUnwrap)
    {
        if (!File.Exists(path))
        {
            throw new CliError($"Recipient key file '{path}' does not exist.");
        }

        string text = File.ReadAllText(path).Trim();
        try
        {
            if (text.StartsWith(PrivatePrefix, StringComparison.Ordinal))
            {
                return Hybrid.HybridKemContentKeyProvider.ImportPrivateKey(
                    Convert.FromBase64String(text.Substring(PrivatePrefix.Length)));
            }

            if (text.StartsWith(PublicPrefix, StringComparison.Ordinal))
            {
                if (needUnwrap)
                {
                    throw new CliError(
                        $"'{path}' is a public key, which can seal but not open. Decrypting needs the " +
                        $"private key file (prefix '{PrivatePrefix}').");
                }

                return Hybrid.HybridKemContentKeyProvider.ImportPublicKey(
                    Convert.FromBase64String(text.Substring(PublicPrefix.Length)));
            }
        }
        catch (FormatException)
        {
            throw new CliError($"'{path}' is not a valid hybrid key file (corrupted or truncated).");
        }

        throw new CliError(
            $"'{path}' is not a hybrid key file (expected a '{PublicPrefix}' or '{PrivatePrefix}' prefix). " +
            "Generate one with 'pqc-config keygen'.");
    }

    private static void ThrowIfExists(string path)
    {
        if (File.Exists(path))
        {
            throw new CliError($"'{path}' already exists — refusing to overwrite key material. Move it aside first.");
        }
    }
#else
    /// <summary>Not available before .NET 10 — fails with a clear, actionable error.</summary>
    internal static string GenerateAndWrite(string publicPath, string privatePath) => throw RequiresNet10();

    /// <summary>Not available before .NET 10 — fails with a clear, actionable error.</summary>
    internal static IContentKeyProvider Load(string path, bool needUnwrap) => throw RequiresNet10();

    private static CliError RequiresNet10() => new(
        $"Hybrid (ML-KEM) key operations require the .NET 10 runtime; this invocation is running on " +
        $".NET {Environment.Version}. Install the .NET 10 runtime and re-run.");
#endif
}
