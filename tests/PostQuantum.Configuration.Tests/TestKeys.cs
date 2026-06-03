using PostQuantum.KeyManagement;
using PostQuantum.KeyManagement.Local;

namespace PostQuantum.Configuration.Tests;

/// <summary>
/// Shared helpers for building key providers and protectors in tests. Uses the Argon2id
/// <see cref="LocalKekOptions.LowMemory"/> preset so the suite stays fast while still exercising the
/// real local provider end to end.
/// </summary>
internal static class TestKeys
{
    internal const string Passphrase = "correct horse battery staple — test only";

    internal static LocalContentKeyProvider NewProvider(string? passphrase = null) =>
        LocalContentKeyProvider.Create(passphrase ?? Passphrase, LocalKekOptions.LowMemory);

    internal static (IConfigurationProtector Protector, LocalContentKeyProvider Provider) NewProtector(string? passphrase = null)
    {
        LocalContentKeyProvider provider = NewProvider(passphrase);
        return (new PostQuantumConfigProtector(provider), provider);
    }
}
