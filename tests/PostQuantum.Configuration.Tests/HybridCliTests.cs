using System.IO;
using System.Text.Json.Nodes;
using PostQuantum.Configuration.Tool;
using PostQuantum.KeyManagement;
using Xunit;

namespace PostQuantum.Configuration.Tests;

/// <summary>
/// The hybrid (ML-KEM-768 + ECDH P-256) CLI plumbing: <c>keygen</c> key files, wrap-only vs. private
/// loading, and the keyring → recipient migration path through <c>reprotect-file</c>'s engine.
/// Skips cleanly on hosts without ML-KEM.
/// </summary>
public class HybridCliTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("pqc-hybrid-cli-tests-").FullName;

    private string PathFor(string name) => Path.Combine(_dir, name);

    public void Dispose()
    {
        Directory.Delete(_dir, recursive: true);
        GC.SuppressFinalize(this);
    }

    [MLKemFact]
    public void GenerateAndWrite_ProducesPrefixedKeyFiles_AndAFingerprintKeyId()
    {
        string pub = PathFor("r.pub");
        string priv = PathFor("r.key");

        string keyId = HybridKeyFiles.GenerateAndWrite(pub, priv);

        Assert.StartsWith("hk-", keyId, StringComparison.Ordinal);
        Assert.StartsWith(HybridKeyFiles.PublicPrefix, File.ReadAllText(pub), StringComparison.Ordinal);
        Assert.StartsWith(HybridKeyFiles.PrivatePrefix, File.ReadAllText(priv), StringComparison.Ordinal);
    }

    [MLKemFact]
    public void GenerateAndWrite_RefusesToOverwriteExistingKeyMaterial()
    {
        string pub = PathFor("r.pub");
        string priv = PathFor("r.key");
        HybridKeyFiles.GenerateAndWrite(pub, priv);

        Assert.Throws<CliError>(() => HybridKeyFiles.GenerateAndWrite(pub, PathFor("other.key")));
        Assert.Throws<CliError>(() => HybridKeyFiles.GenerateAndWrite(PathFor("other.pub"), priv));
    }

    [MLKemFact]
    public void PublicKeySeals_PrivateKeyOpens_RoundTrip()
    {
        string pub = PathFor("r.pub");
        string priv = PathFor("r.key");
        HybridKeyFiles.GenerateAndWrite(pub, priv);

        IContentKeyProvider sealer = HybridKeyFiles.Load(pub, needUnwrap: false);
        IContentKeyProvider opener = HybridKeyFiles.Load(priv, needUnwrap: true);
        using var sealerOwnership = (IDisposable)sealer;
        using var openerOwnership = (IDisposable)opener;

        string token = new PostQuantumConfigProtector(sealer).Protect("Host=db;Password=quantum-safe");
        Assert.Equal("Host=db;Password=quantum-safe", new PostQuantumConfigProtector(opener).Unprotect(token));
    }

    [MLKemFact]
    public void Load_FailsClosed_OnWrongOrCorruptKeyFiles()
    {
        string pub = PathFor("r.pub");
        string priv = PathFor("r.key");
        HybridKeyFiles.GenerateAndWrite(pub, priv);

        // A public key where decryption is required — must be a clear error, not a late unwrap failure.
        Assert.Throws<CliError>(() => HybridKeyFiles.Load(pub, needUnwrap: true));

        // A missing, foreign, or truncated file is a clear error too.
        Assert.Throws<CliError>(() => HybridKeyFiles.Load(PathFor("missing.pub"), needUnwrap: false));

        string foreign = PathFor("keyring.txt");
        File.WriteAllText(foreign, "not a hybrid key file");
        Assert.Throws<CliError>(() => HybridKeyFiles.Load(foreign, needUnwrap: false));

        string truncated = PathFor("truncated.pub");
        File.WriteAllText(truncated, HybridKeyFiles.PublicPrefix + "AAAA!!!not-base64");
        Assert.Throws<CliError>(() => HybridKeyFiles.Load(truncated, needUnwrap: false));
    }

    [MLKemFact]
    public void CrossProviderTokens_FailClosed_WithTheOpaqueException()
    {
        string pub = PathFor("r.pub");
        string priv = PathFor("r.key");
        HybridKeyFiles.GenerateAndWrite(pub, priv);
        IContentKeyProvider hybrid = HybridKeyFiles.Load(priv, needUnwrap: true);
        using var ownership = (IDisposable)hybrid;
        var hybridProtector = new PostQuantumConfigProtector(hybrid);

        (IConfigurationProtector keyringProtector, var localProvider) = TestKeys.NewProtector();
        using (localProvider)
        {
            // A hybrid token handed to the keyring protector (and vice versa) must surface as the one
            // opaque failure type — never the provider's raw "wrong provider family" exception.
            string hybridToken = hybridProtector.Protect("secret");
            Assert.Throws<ConfigurationProtectionException>(() => keyringProtector.Unprotect(hybridToken));
            Assert.False(keyringProtector.TryUnprotect(hybridToken, out _));

            string localToken = keyringProtector.Protect("secret");
            Assert.Throws<ConfigurationProtectionException>(() => hybridProtector.Unprotect(localToken));

            // A wrap-only (public key) provider asked to open its own recipient's token: same contract.
            IContentKeyProvider wrapOnly = HybridKeyFiles.Load(pub, needUnwrap: false);
            using var wrapOnlyOwnership = (IDisposable)wrapOnly;
            Assert.Throws<ConfigurationProtectionException>(
                () => new PostQuantumConfigProtector(wrapOnly).Unprotect(hybridToken));
        }
    }

    [MLKemFact]
    public void HybridTokens_InspectAsHybrid_WithTheRecipientFingerprint()
    {
        string pub = PathFor("r.pub");
        string priv = PathFor("r.key");
        string keyId = HybridKeyFiles.GenerateAndWrite(pub, priv);

        IContentKeyProvider sealer = HybridKeyFiles.Load(pub, needUnwrap: false);
        using var ownership = (IDisposable)sealer;
        string token = new PostQuantumConfigProtector(sealer).Protect("secret");

        Assert.True(ProtectedTokenInfo.TryInspect(token, out ProtectedTokenInfo? info));
        Assert.Equal("hybrid-mlkem768-ecdhp256", info!.ProviderId);
        Assert.Equal(keyId, info.KeyId);
    }

    [MLKemFact]
    public void ReprotectFile_MigratesAKeyringSealedFile_OntoHybridWrapping()
    {
        // Seal a file with the local (symmetric) keyring — the starting point of most deployments.
        (IConfigurationProtector keyringProtector, var provider) = TestKeys.NewProtector();
        using (provider)
        {
            var root = (JsonObject)JsonNode.Parse(
                """{ "ConnectionStrings": { "Default": "Host=db;Password=s3cr3t" }, "Note": "plain" }""")!;
            FileProtection.Protect(
                root, keyringProtector, KeySelector.FromOptions(null, null, all: true), bindKeyAsContext: false, dryRun: false);

            // Migrate: keyring opens, the recipient's PUBLIC key seals.
            string pub = PathFor("r.pub");
            string priv = PathFor("r.key");
            HybridKeyFiles.GenerateAndWrite(pub, priv);
            IContentKeyProvider sealerProvider = HybridKeyFiles.Load(pub, needUnwrap: false);
            using var sealerOwnership = (IDisposable)sealerProvider;
            var hybridSealer = new PostQuantumConfigProtector(sealerProvider);

            FileProtectionResult result = FileProtection.Reprotect(
                root, keyringProtector, hybridSealer, bindKeyAsContext: false, dryRun: false);
            Assert.Equal(2, result.ChangedKeys.Count);

            // The tokens are now post-quantum-wrapped, and only the private key opens them.
            string token = (string)root["ConnectionStrings"]!["Default"]!;
            Assert.True(ProtectedTokenInfo.TryInspect(token, out ProtectedTokenInfo? info));
            Assert.Equal("hybrid-mlkem768-ecdhp256", info!.ProviderId);
            Assert.False(keyringProtector.TryUnprotect(token, out _));

            IContentKeyProvider openerProvider = HybridKeyFiles.Load(priv, needUnwrap: true);
            using var openerOwnership = (IDisposable)openerProvider;
            Assert.Equal("Host=db;Password=s3cr3t", new PostQuantumConfigProtector(openerProvider).Unprotect(token));
        }
    }
}
