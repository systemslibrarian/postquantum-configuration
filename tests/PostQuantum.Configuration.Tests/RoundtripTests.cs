using Xunit;

namespace PostQuantum.Configuration.Tests;

public sealed class RoundtripTests
{
    [Theory]
    [InlineData("Server=db;Database=app;User Id=svc;Password=hunter2;")]
    [InlineData("sk-live-0123456789abcdef")]
    [InlineData("")]
    [InlineData("a")]
    [InlineData("unicode: café — façade — 🔐 — Ω")]
    [InlineData("{\"nested\":\"json section\",\"n\":42}")]
    public void Protect_then_Unprotect_returns_the_original_value(string plaintext)
    {
        var (protector, provider) = TestKeys.NewProtector();
        using (provider)
        {
            string token = protector.Protect(plaintext);
            string recovered = protector.Unprotect(token);
            Assert.Equal(plaintext, recovered);
        }
    }

    [Fact]
    public async Task ProtectAsync_then_UnprotectAsync_returns_the_original_value()
    {
        var (protector, provider) = TestKeys.NewProtector();
        using (provider)
        {
            const string plaintext = "Server=db;Password=async-secret;";
            string token = await protector.ProtectAsync(plaintext);
            string recovered = await protector.UnprotectAsync(token);
            Assert.Equal(plaintext, recovered);
        }
    }

    [Fact]
    public void A_protected_token_carries_the_recognisable_prefix()
    {
        var (protector, provider) = TestKeys.NewProtector();
        using (provider)
        {
            string token = protector.Protect("value");
            Assert.StartsWith("pqc.v1.", token);
            Assert.True(IConfigurationProtector.IsProtected(token));
        }
    }

    [Fact]
    public void Protecting_the_same_value_twice_yields_distinct_tokens()
    {
        var (protector, provider) = TestKeys.NewProtector();
        using (provider)
        {
            // Fresh content key + fresh nonce per call → ciphertexts must differ (no deterministic leak).
            string first = protector.Protect("same value");
            string second = protector.Protect("same value");
            Assert.NotEqual(first, second);
            Assert.Equal("same value", protector.Unprotect(first));
            Assert.Equal("same value", protector.Unprotect(second));
        }
    }

    [Fact]
    public void A_long_value_roundtrips()
    {
        var (protector, provider) = TestKeys.NewProtector();
        using (provider)
        {
            string plaintext = new string('x', 100_000);
            string token = protector.Protect(plaintext);
            Assert.Equal(plaintext, protector.Unprotect(token));
        }
    }

    [Fact]
    public void TryUnprotect_succeeds_for_a_valid_token()
    {
        var (protector, provider) = TestKeys.NewProtector();
        using (provider)
        {
            string token = protector.Protect("ok");
            Assert.True(protector.TryUnprotect(token, out string? plaintext));
            Assert.Equal("ok", plaintext);
        }
    }

    [Fact]
    public void IsProtected_is_false_for_plaintext_and_null()
    {
        Assert.False(IConfigurationProtector.IsProtected(null));
        Assert.False(IConfigurationProtector.IsProtected(""));
        Assert.False(IConfigurationProtector.IsProtected("just a plain connection string"));
        Assert.False(IConfigurationProtector.IsProtected("pqc.v2.something")); // wrong version prefix
    }

    [Fact]
    public void Tokens_remain_decryptable_after_a_key_rotation()
    {
        // Rotation adds a new active KEK but keeps old ones for unwrapping — old tokens still open.
        using PostQuantum.KeyManagement.Local.LocalContentKeyProvider provider = TestKeys.NewProvider();
        var protector = new PostQuantumConfigProtector(provider);

        string token = protector.Protect("pre-rotation secret");
        provider.Rotate("a new passphrase entirely", PostQuantum.KeyManagement.Local.LocalKekOptions.LowMemory);

        Assert.Equal("pre-rotation secret", protector.Unprotect(token));

        // New values seal under the new active KEK and also roundtrip.
        string after = protector.Protect("post-rotation secret");
        Assert.Equal("post-rotation secret", protector.Unprotect(after));
    }
}
