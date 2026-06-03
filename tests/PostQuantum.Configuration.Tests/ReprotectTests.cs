using System.Collections.Generic;
using PostQuantum.KeyManagement.Local;
using Xunit;

namespace PostQuantum.Configuration.Tests;

public sealed class ReprotectTests
{
    [Fact]
    public void Reprotect_produces_a_new_token_that_still_decrypts()
    {
        using LocalContentKeyProvider provider = TestKeys.NewProvider();
        var protector = new PostQuantumConfigProtector(provider);

        string original = protector.Protect("rotate me");
        string reprotected = protector.Reprotect(original);

        Assert.NotEqual(original, reprotected);
        Assert.Equal("rotate me", protector.Unprotect(reprotected));
    }

    [Fact]
    public void Reprotect_after_rotation_migrates_to_the_new_active_key()
    {
        using LocalContentKeyProvider provider = TestKeys.NewProvider();
        var protector = new PostQuantumConfigProtector(provider);

        string token = protector.Protect("secret");
        string oldActiveKey = provider.ActiveKeyId;

        provider.Rotate("a new passphrase", LocalKekOptions.LowMemory);
        Assert.NotEqual(oldActiveKey, provider.ActiveKeyId);

        // Re-sealed value opens under the new active key, and the plaintext is preserved.
        string reprotected = protector.Reprotect(token);
        Assert.Equal("secret", protector.Unprotect(reprotected));
    }

    [Fact]
    public void Reprotect_preserves_context()
    {
        using LocalContentKeyProvider provider = TestKeys.NewProvider();
        var protector = new PostQuantumConfigProtector(provider);

        string token = protector.Protect("ctx secret", context: "slot-A");
        string reprotected = protector.Reprotect(token, context: "slot-A");

        Assert.Equal("ctx secret", protector.Unprotect(reprotected, context: "slot-A"));
        Assert.Throws<ConfigurationProtectionException>(() => protector.Unprotect(reprotected, context: "slot-B"));
    }

    [Fact]
    public async Task ReprotectAllAsync_reseals_only_protected_values()
    {
        using LocalContentKeyProvider provider = TestKeys.NewProvider();
        var protector = new PostQuantumConfigProtector(provider);

        var values = new Dictionary<string, string?>
        {
            ["ConnectionStrings:Default"] = protector.Protect("Host=db;Password=p1;"),
            ["Secrets:ApiKey"] = protector.Protect("sk-123"),
            ["Logging:LogLevel:Default"] = "Information", // plaintext — must be left alone
            ["Empty"] = null,
        };

        Dictionary<string, string?> before = new(values);

        int resealed = await protector.ReprotectAllAsync(values);

        Assert.Equal(2, resealed);
        Assert.NotEqual(before["ConnectionStrings:Default"], values["ConnectionStrings:Default"]);
        Assert.NotEqual(before["Secrets:ApiKey"], values["Secrets:ApiKey"]);
        Assert.Equal("Information", values["Logging:LogLevel:Default"]); // untouched
        Assert.Null(values["Empty"]);

        Assert.Equal("Host=db;Password=p1;", protector.Unprotect(values["ConnectionStrings:Default"]!));
        Assert.Equal("sk-123", protector.Unprotect(values["Secrets:ApiKey"]!));
    }

    [Fact]
    public async Task ReprotectAllAsync_leaves_the_map_untouched_when_any_token_is_bad()
    {
        using LocalContentKeyProvider provider = TestKeys.NewProvider();
        var protector = new PostQuantumConfigProtector(provider);

        var values = new Dictionary<string, string?>
        {
            ["Good"] = protector.Protect("keep me"),
            // Carries the pqc.v1 prefix (so it's treated as a token) but is malformed — must abort the batch.
            ["Bad"] = "pqc.v1.not-a-real-token",
            ["Plain"] = "untouched",
        };
        Dictionary<string, string?> before = new(values);

        await Assert.ThrowsAsync<ConfigurationProtectionException>(() => protector.ReprotectAllAsync(values));

        // All-or-nothing: nothing was committed, so every entry is byte-for-byte what it was.
        Assert.Equal(before["Good"], values["Good"]);
        Assert.Equal(before["Bad"], values["Bad"]);
        Assert.Equal(before["Plain"], values["Plain"]);

        // And the surviving good token still opens to its original plaintext.
        Assert.Equal("keep me", protector.Unprotect(values["Good"]!));
    }

    [Fact]
    public async Task ReprotectAllAsync_with_bindKeyAsContext_reseals_under_each_key()
    {
        using LocalContentKeyProvider provider = TestKeys.NewProvider();
        var protector = new PostQuantumConfigProtector(provider);

        const string key = "ConnectionStrings:Default";
        var values = new Dictionary<string, string?> { [key] = protector.Protect("secret", context: key) };

        int resealed = await protector.ReprotectAllAsync(values, bindKeyAsContext: true);

        Assert.Equal(1, resealed);
        Assert.Equal("secret", protector.Unprotect(values[key]!, context: key));
    }
}
