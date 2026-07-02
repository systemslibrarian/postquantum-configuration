using System.Text.Json.Nodes;
using System.Threading.Tasks;
using PostQuantum.Configuration.Tool;
using Xunit;

namespace PostQuantum.Configuration.Tests;

/// <summary>
/// The defensive guardrails: the <see cref="VerificationExtensions"/> startup self-test, the keyless
/// <c>audit</c> heuristics, and the <c>check</c> pre-deploy gate.
/// </summary>
public class GuardrailTests
{
    private static JsonObject Parse(string json) => (JsonObject)JsonNode.Parse(json)!;

    // --- VerifyAsync -------------------------------------------------------------------------------

    [Fact]
    public async Task VerifyAsync_Succeeds_WhenTheKeySourceCanSealAndOpen()
    {
        (IConfigurationProtector protector, var provider) = TestKeys.NewProtector();
        using (provider)
        {
            await protector.VerifyAsync();
            protector.Verify(); // sync companion
        }
    }

    [MLKemFact]
    public async Task VerifyAsync_FailsClosed_ForAWrapOnlyProvider()
    {
        using var recipient = Hybrid.HybridKemContentKeyProvider.Generate();
        using var wrapOnly = Hybrid.HybridKemContentKeyProvider.ImportPublicKey(recipient.ExportPublicKey());

        // A public-only provider can seal but never open — it must not pass a decrypt-readiness check.
        await Assert.ThrowsAsync<ConfigurationProtectionException>(
            () => new PostQuantumConfigProtector(wrapOnly).VerifyAsync());
    }

    // --- audit -------------------------------------------------------------------------------------

    [Fact]
    public void Audit_FlagsSensitiveKeyNames_AndEmbeddedCredentials()
    {
        JsonObject root = Parse("""
            {
              "ConnectionStrings": { "Default": "Host=db;Password=s3cr3t" },
              "Stripe": { "ApiKey": "sk-live-123" },
              "Auth": { "ClientSecret": "abc" },
              "Innocent": "Server=db;User Id=reader;Password=oops",
              "Logging": { "Level": "Information" },
              "Port": 8080
            }
            """);

        FileAuditResult result = FileProtection.Audit(root);

        Assert.Contains("ConnectionStrings:Default", result.SuspectKeys); // sensitive section name
        Assert.Contains("Stripe:ApiKey", result.SuspectKeys);             // sensitive key name
        Assert.Contains("Auth:ClientSecret", result.SuspectKeys);         // "secret" fragment
        Assert.Contains("Innocent", result.SuspectKeys);                  // embedded "Password=" in the value
        Assert.DoesNotContain("Logging:Level", result.SuspectKeys);
        Assert.Equal(4, result.SuspectKeys.Count);
    }

    [Fact]
    public void Audit_DoesNotFlagProtectedValues_AndCountsThem()
    {
        (IConfigurationProtector protector, var provider) = TestKeys.NewProtector();
        using (provider)
        {
            JsonObject root = Parse("""{ "Db": { "Password": "s3cr3t" }, "Other": "plain" }""");
            FileProtection.Protect(
                root, protector, KeySelector.FromOptions(null, null, all: true), bindKeyAsContext: false, dryRun: false);

            FileAuditResult result = FileProtection.Audit(root);

            Assert.Empty(result.SuspectKeys);
            Assert.Equal(2, result.ProtectedCount);
        }
    }

    // --- check -------------------------------------------------------------------------------------

    [Fact]
    public void Check_Passes_WhenEveryTokenDecrypts_AndRequirementsAreMet()
    {
        (IConfigurationProtector protector, var provider) = TestKeys.NewProtector();
        using (provider)
        {
            JsonObject root = Parse("""{ "Db": { "Password": "s3cr3t" }, "Note": "plain" }""");
            FileProtection.Protect(
                root, protector, KeySelector.FromOptions("Db:Password", null, all: false), bindKeyAsContext: false, dryRun: false);

            FileCheckResult result = FileProtection.Check(root, protector, bindKeyAsContext: false, ["Db:Password"]);

            Assert.True(result.Passed);
            Assert.Equal(1, result.TokensChecked);
        }
    }

    [Fact]
    public void Check_Fails_WhenATokenDoesNotDecryptWithThisKeySource()
    {
        (IConfigurationProtector alice, var aliceProvider) = TestKeys.NewProtector("alice's passphrase");
        (IConfigurationProtector bob, var bobProvider) = TestKeys.NewProtector("bob's different passphrase");
        using (aliceProvider)
        using (bobProvider)
        {
            JsonObject root = Parse("""{ "Db": { "Password": "s3cr3t" } }""");
            FileProtection.Protect(
                root, alice, KeySelector.FromOptions(null, null, all: true), bindKeyAsContext: false, dryRun: false);

            FileCheckResult result = FileProtection.Check(root, bob, bindKeyAsContext: false, []);

            Assert.False(result.Passed);
            Assert.Equal(["Db:Password"], result.FailedKeys);
        }
    }

    [Fact]
    public void Check_Fails_WhenARequiredKeyIsPlaintextOrMissing()
    {
        (IConfigurationProtector protector, var provider) = TestKeys.NewProtector();
        using (provider)
        {
            JsonObject root = Parse("""{ "Db": { "Password": "still plaintext!" } }""");

            FileCheckResult result = FileProtection.Check(
                root, protector, bindKeyAsContext: false, ["Db:Password", "Stripe:ApiKey"]);

            Assert.False(result.Passed);
            Assert.Equal(0, result.TokensChecked);
            Assert.Contains("Db:Password (present but NOT protected)", result.UnmetRequirements);
            Assert.Contains("Stripe:ApiKey (missing)", result.UnmetRequirements);
        }
    }

    [Fact]
    public void Check_HonoursKeyBinding_InBothDirections()
    {
        (IConfigurationProtector protector, var provider) = TestKeys.NewProtector();
        using (provider)
        {
            JsonObject root = Parse("""{ "Db": { "Password": "s3cr3t" } }""");
            FileProtection.Protect(
                root, protector, KeySelector.FromOptions(null, null, all: true), bindKeyAsContext: true, dryRun: false);

            Assert.True(FileProtection.Check(root, protector, bindKeyAsContext: true, []).Passed);
            // Checking without the binding must fail — exactly as the transparent layer would at runtime.
            Assert.False(FileProtection.Check(root, protector, bindKeyAsContext: false, []).Passed);
        }
    }
}
