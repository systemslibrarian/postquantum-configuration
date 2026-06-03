using System.Collections.Generic;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace PostQuantum.Configuration.Tests;

public sealed class ConfigurationProtectorExtensionsTests
{
    [Fact]
    public void GetDecrypted_decrypts_a_protected_value_and_passes_plaintext_through()
    {
        var (protector, provider) = TestKeys.NewProtector();
        using (provider)
        {
            string token = protector.Protect("secret value");
            IConfiguration config = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Encrypted"] = token,
                    ["Plain"] = "plain value",
                })
                .Build();

            Assert.Equal("secret value", config.GetDecrypted("Encrypted", protector));
            Assert.Equal("plain value", config.GetDecrypted("Plain", protector));
            Assert.Null(config.GetDecrypted("Missing", protector));
        }
    }

    [Fact]
    public void DecryptIfProtected_is_a_passthrough_for_non_tokens()
    {
        var (protector, provider) = TestKeys.NewProtector();
        using (provider)
        {
            Assert.Null(protector.DecryptIfProtected(null));
            Assert.Equal("", protector.DecryptIfProtected(""));
            Assert.Equal("plain", protector.DecryptIfProtected("plain"));

            string token = protector.Protect("hidden");
            Assert.Equal("hidden", protector.DecryptIfProtected(token));
        }
    }
}
