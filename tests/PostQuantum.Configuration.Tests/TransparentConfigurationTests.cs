using System.Collections.Generic;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Memory;
using Xunit;

namespace PostQuantum.Configuration.Tests;

public sealed class TransparentConfigurationTests
{
    private static MemoryConfigurationSource MemorySource(IEnumerable<KeyValuePair<string, string?>> data) =>
        new() { InitialData = data };

    [Fact]
    public void Protected_values_are_decrypted_transparently_on_read()
    {
        var (protector, provider) = TestKeys.NewProtector();
        using (provider)
        {
            string token = protector.Protect("Server=db;Password=p@ss;");

            IConfiguration config = new ConfigurationBuilder()
                .AddEncrypted(
                    MemorySource(new Dictionary<string, string?>
                    {
                        ["ConnectionStrings:Default"] = token,
                        ["Logging:LogLevel:Default"] = "Information",
                    }),
                    protector)
                .Build();

            Assert.Equal("Server=db;Password=p@ss;", config["ConnectionStrings:Default"]);
            // Plaintext values pass straight through.
            Assert.Equal("Information", config["Logging:LogLevel:Default"]);
        }
    }

    [Fact]
    public void GetConnectionString_returns_the_decrypted_value()
    {
        var (protector, provider) = TestKeys.NewProtector();
        using (provider)
        {
            string token = protector.Protect("Server=db;Database=app;");

            IConfiguration config = new ConfigurationBuilder()
                .AddEncrypted(
                    MemorySource(new Dictionary<string, string?> { ["ConnectionStrings:App"] = token }),
                    protector)
                .Build();

            Assert.Equal("Server=db;Database=app;", config.GetConnectionString("App"));
        }
    }

    [Fact]
    public void Child_keys_are_still_enumerable_through_the_wrapper()
    {
        var (protector, provider) = TestKeys.NewProtector();
        using (provider)
        {
            IConfiguration config = new ConfigurationBuilder()
                .AddEncrypted(
                    MemorySource(new Dictionary<string, string?>
                    {
                        ["Section:A"] = protector.Protect("alpha"),
                        ["Section:B"] = "beta",
                    }),
                    protector)
                .Build();

            IConfigurationSection section = config.GetSection("Section");
            Dictionary<string, string?> values = section.GetChildren()
                .ToDictionary(c => c.Key, c => c.Value);

            Assert.Equal("alpha", values["A"]);
            Assert.Equal("beta", values["B"]);
        }
    }

    [Fact]
    public void The_factory_is_invoked_lazily_only_when_a_protected_value_is_read()
    {
        var (protector, provider) = TestKeys.NewProtector();
        using (provider)
        {
            int factoryCalls = 0;
            IConfiguration config = new ConfigurationBuilder()
                .AddEncrypted(
                    MemorySource(new Dictionary<string, string?> { ["Plain"] = "no secrets here" }),
                    () => { factoryCalls++; return protector; })
                .Build();

            // Reading only plaintext must not force the protector to materialise.
            Assert.Equal("no secrets here", config["Plain"]);
            Assert.Equal(0, factoryCalls);
        }
    }

    [Fact]
    public void Repeated_reads_decrypt_once_and_cache()
    {
        var (protector, provider) = TestKeys.NewProtector();
        using (provider)
        {
            int factoryCalls = 0;
            string token = protector.Protect("cached secret");
            IConfiguration config = new ConfigurationBuilder()
                .AddEncrypted(
                    MemorySource(new Dictionary<string, string?> { ["Secret"] = token }),
                    () => { factoryCalls++; return protector; })
                .Build();

            Assert.Equal("cached secret", config["Secret"]);
            Assert.Equal("cached secret", config["Secret"]);
            Assert.Equal(1, factoryCalls); // resolved once, then served from cache
        }
    }

    [Fact]
    public void BindKeyAsContext_decrypts_when_the_value_was_sealed_with_its_key()
    {
        var (protector, provider) = TestKeys.NewProtector();
        using (provider)
        {
            const string key = "ConnectionStrings:Default";
            string token = protector.Protect("ctx-bound secret", context: key);

            IConfiguration config = new ConfigurationBuilder()
                .AddEncrypted(
                    MemorySource(new Dictionary<string, string?> { [key] = token }),
                    protector,
                    bindKeyAsContext: true)
                .Build();

            Assert.Equal("ctx-bound secret", config[key]);
        }
    }

    [Fact]
    public void BindKeyAsContext_rejects_a_value_moved_to_a_different_key()
    {
        var (protector, provider) = TestKeys.NewProtector();
        using (provider)
        {
            // Sealed for one key, but planted under another — context binding must reject it.
            string token = protector.Protect("secret", context: "ConnectionStrings:Default");

            IConfiguration config = new ConfigurationBuilder()
                .AddEncrypted(
                    MemorySource(new Dictionary<string, string?> { ["ConnectionStrings:Replica"] = token }),
                    protector,
                    bindKeyAsContext: true)
                .Build();

            Assert.Throws<ConfigurationProtectionException>(() => _ = config["ConnectionStrings:Replica"]);
        }
    }
}
