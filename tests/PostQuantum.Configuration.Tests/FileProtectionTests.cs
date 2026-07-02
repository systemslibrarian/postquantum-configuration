using System.IO;
using System.Text.Json.Nodes;
using PostQuantum.Configuration.Tool;
using PostQuantum.KeyManagement.Local;
using Xunit;

namespace PostQuantum.Configuration.Tests;

/// <summary>
/// The <c>protect-file</c> / <c>reprotect-file</c> engine: selection semantics, idempotency, context
/// binding, all-or-nothing failure, and the strict-JSON load / atomic save around it.
/// </summary>
public class FileProtectionTests
{
    private const string SampleJson = """
        {
          "ConnectionStrings": {
            "Default": "Host=db;Password=s3cr3t",
            "Replica": "Host=db2;Password=s3cr3t"
          },
          "ApiKeys": ["key-one", "key-two"],
          "Logging": { "Level": "Information" },
          "Port": 8080,
          "Enabled": true,
          "Nothing": null
        }
        """;

    private static JsonObject Parse(string json) => (JsonObject)JsonNode.Parse(json)!;

    // --- selection ---------------------------------------------------------------------------------

    [Fact]
    public void Protect_All_SealsEveryStringLeaf_AndOnlyStrings()
    {
        (IConfigurationProtector protector, LocalContentKeyProvider provider) = TestKeys.NewProtector();
        using (provider)
        {
            JsonObject root = Parse(SampleJson);
            FileProtectionResult result = FileProtection.Protect(
                root, protector, KeySelector.FromOptions(null, null, all: true), bindKeyAsContext: false, dryRun: false);

            // 5 string leaves: 2 connection strings, 2 array entries, the logging level.
            Assert.Equal(5, result.ChangedKeys.Count);
            Assert.Contains("ConnectionStrings:Default", result.ChangedKeys);
            Assert.Contains("ApiKeys:0", result.ChangedKeys);
            Assert.Contains("ApiKeys:1", result.ChangedKeys);

            Assert.True(IConfigurationProtector.IsProtected((string?)root["ConnectionStrings"]!["Default"]));
            Assert.True(IConfigurationProtector.IsProtected((string?)root["ApiKeys"]![1]));
            Assert.Equal("secret", protector.Unprotect(protector.Protect("secret"))); // sanity: same keyring opens them

            // Non-string leaves are untouched, types preserved.
            Assert.Equal(8080, (int)root["Port"]!);
            Assert.True((bool)root["Enabled"]!);
            Assert.Null(root["Nothing"]);
        }
    }

    [Fact]
    public void Protect_Section_SealsOnlyThatSubtree_CaseInsensitively()
    {
        (IConfigurationProtector protector, LocalContentKeyProvider provider) = TestKeys.NewProtector();
        using (provider)
        {
            JsonObject root = Parse(SampleJson);
            FileProtection.Protect(
                root, protector, KeySelector.FromOptions(null, "connectionstrings", all: false), bindKeyAsContext: false, dryRun: false);

            Assert.True(IConfigurationProtector.IsProtected((string?)root["ConnectionStrings"]!["Default"]));
            Assert.True(IConfigurationProtector.IsProtected((string?)root["ConnectionStrings"]!["Replica"]));
            Assert.Equal("key-one", (string?)root["ApiKeys"]![0]);
            Assert.Equal("Information", (string?)root["Logging"]!["Level"]);
        }
    }

    [Fact]
    public void Protect_Keys_SealsExactlyThoseKeys()
    {
        (IConfigurationProtector protector, LocalContentKeyProvider provider) = TestKeys.NewProtector();
        using (provider)
        {
            JsonObject root = Parse(SampleJson);
            FileProtection.Protect(
                root,
                protector,
                KeySelector.FromOptions("ConnectionStrings:Default,ApiKeys:0", null, all: false),
                bindKeyAsContext: false,
                dryRun: false);

            Assert.True(IConfigurationProtector.IsProtected((string?)root["ConnectionStrings"]!["Default"]));
            Assert.True(IConfigurationProtector.IsProtected((string?)root["ApiKeys"]![0]));
            Assert.Equal("Host=db2;Password=s3cr3t", (string?)root["ConnectionStrings"]!["Replica"]);
            Assert.Equal("key-two", (string?)root["ApiKeys"]![1]);
        }
    }

    [Theory]
    [InlineData("ConnectionStrings:Missing")] // typo'd key
    [InlineData("Port")]                      // exists, but is a number — cannot be protected
    public void Protect_Keys_FailsClosed_WhenARequestedKeyIsNotAStringLeaf(string key)
    {
        (IConfigurationProtector protector, LocalContentKeyProvider provider) = TestKeys.NewProtector();
        using (provider)
        {
            JsonObject root = Parse(SampleJson);
            Assert.Throws<CliError>(() => FileProtection.Protect(
                root, protector, KeySelector.FromOptions(key, null, all: false), bindKeyAsContext: false, dryRun: false));
        }
    }

    [Fact]
    public void KeySelector_RequiresExactlyOneSelectionMode()
    {
        Assert.Throws<CliError>(() => KeySelector.FromOptions(null, null, all: false));
        Assert.Throws<CliError>(() => KeySelector.FromOptions("A", "B", all: false));
        Assert.Throws<CliError>(() => KeySelector.FromOptions("A", null, all: true));
        Assert.Throws<CliError>(() => KeySelector.FromOptions(",", null, all: false)); // no keys after trimming
    }

    // --- idempotency, binding, dry-run --------------------------------------------------------------

    [Fact]
    public void Protect_IsIdempotent_TokensAreSkippedOnRerun()
    {
        (IConfigurationProtector protector, LocalContentKeyProvider provider) = TestKeys.NewProtector();
        using (provider)
        {
            JsonObject root = Parse(SampleJson);
            KeySelector All() => KeySelector.FromOptions(null, null, all: true);

            FileProtectionResult first = FileProtection.Protect(root, protector, All(), bindKeyAsContext: false, dryRun: false);
            FileProtectionResult second = FileProtection.Protect(root, protector, All(), bindKeyAsContext: false, dryRun: false);

            Assert.Equal(5, first.ChangedKeys.Count);
            Assert.Empty(second.ChangedKeys);
            Assert.Equal(5, second.AlreadyProtected);
        }
    }

    [Fact]
    public void Protect_BindKey_SealsEachValueToItsConfigurationKey()
    {
        (IConfigurationProtector protector, LocalContentKeyProvider provider) = TestKeys.NewProtector();
        using (provider)
        {
            JsonObject root = Parse(SampleJson);
            FileProtection.Protect(
                root, protector, KeySelector.FromOptions(null, null, all: true), bindKeyAsContext: true, dryRun: false);

            string token = (string)root["ConnectionStrings"]!["Default"]!;
            Assert.Equal("Host=db;Password=s3cr3t", protector.Unprotect(token, context: "ConnectionStrings:Default"));
            Assert.False(protector.TryUnprotect(token, out _));                                        // unbound read fails
            Assert.False(protector.TryUnprotect(token, out _, context: "ConnectionStrings:Replica")); // swapped slot fails
        }
    }

    [Fact]
    public void Protect_DryRun_ReportsKeysWithoutTouchingValues_AndNeedsNoProtector()
    {
        JsonObject root = Parse(SampleJson);
        FileProtectionResult result = FileProtection.Protect(
            root, protector: null, KeySelector.FromOptions(null, null, all: true), bindKeyAsContext: false, dryRun: true);

        Assert.Equal(5, result.ChangedKeys.Count);
        Assert.Equal("Host=db;Password=s3cr3t", (string?)root["ConnectionStrings"]!["Default"]);
    }

    // --- reprotect ----------------------------------------------------------------------------------

    [Fact]
    public void Reprotect_MigratesEveryTokenToTheActiveKey_AndLeavesPlaintextAlone()
    {
        (IConfigurationProtector protector, LocalContentKeyProvider provider) = TestKeys.NewProtector();
        using (provider)
        {
            JsonObject root = Parse(SampleJson);
            FileProtection.Protect(
                root, protector, KeySelector.FromOptions(null, "ConnectionStrings", all: false), bindKeyAsContext: false, dryRun: false);

            string newActiveKeyId = provider.Rotate(TestKeys.Passphrase, LocalKekOptions.LowMemory);
            FileProtectionResult result = FileProtection.Reprotect(root, protector, bindKeyAsContext: false, dryRun: false);

            Assert.Equal(2, result.ChangedKeys.Count);
            string token = (string)root["ConnectionStrings"]!["Default"]!;
            Assert.True(ProtectedTokenInfo.TryInspect(token, out ProtectedTokenInfo? info));
            Assert.Equal(newActiveKeyId, info!.KeyId);
            Assert.Equal("Host=db;Password=s3cr3t", protector.Unprotect(token));
            Assert.Equal("key-one", (string?)root["ApiKeys"]![0]); // plaintext untouched
        }
    }

    [Fact]
    public void Reprotect_FailsClosed_BeforeAnythingIsWritten_WhenATokenIsBogus()
    {
        (IConfigurationProtector protector, LocalContentKeyProvider provider) = TestKeys.NewProtector();
        using (provider)
        {
            // A value that carries the prefix but is not a real token must abort the whole run —
            // the transform throws, so the command never reaches Save() and the file is never touched.
            JsonObject root = Parse("""{ "A": "pqc.v1.AQAAbogus", "B": "plain" }""");
            Assert.Throws<ConfigurationProtectionException>(
                () => FileProtection.Reprotect(root, protector, bindKeyAsContext: false, dryRun: false));
        }
    }

    // --- load / save --------------------------------------------------------------------------------

    [Fact]
    public void Load_RejectsCommentsAndTrailingCommas_BecauseARewriteWouldDestroyThem()
    {
        string path = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName() + ".json");
        try
        {
            File.WriteAllText(path, "{\n  // dev-only note\n  \"A\": \"x\"\n}\n");
            Assert.Throws<CliError>(() => JsonConfigFile.Load(path));

            File.WriteAllText(path, "[1, 2]"); // valid JSON, but not an object root
            Assert.Throws<CliError>(() => JsonConfigFile.Load(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Load_MissingFile_IsAClearError()
    {
        Assert.Throws<CliError>(() => JsonConfigFile.Load(
            Path.Combine(Path.GetTempPath(), Path.GetRandomFileName() + ".json")));
    }

    [Fact]
    public void SaveThenLoad_RoundTripsTheTree()
    {
        string path = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName() + ".json");
        try
        {
            JsonConfigFile.Save(path, Parse(SampleJson));
            JsonObject reloaded = JsonConfigFile.Load(path);

            Assert.Equal("Host=db;Password=s3cr3t", (string?)reloaded["ConnectionStrings"]!["Default"]);
            Assert.Equal(8080, (int)reloaded["Port"]!);
            Assert.Equal(2, reloaded["ApiKeys"]!.AsArray().Count);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
