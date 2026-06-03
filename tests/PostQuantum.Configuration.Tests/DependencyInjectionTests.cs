using Microsoft.Extensions.DependencyInjection;
using PostQuantum.KeyManagement;
using Xunit;

namespace PostQuantum.Configuration.Tests;

public sealed class DependencyInjectionTests
{
    [Fact]
    public void AddPostQuantumConfiguration_resolves_a_working_protector()
    {
        using PostQuantum.KeyManagement.Local.LocalContentKeyProvider keyProvider = TestKeys.NewProvider();

        ServiceProvider services = new ServiceCollection()
            .AddSingleton<IContentKeyProvider>(keyProvider)
            .AddPostQuantumConfiguration()
            .BuildServiceProvider();

        var protector = services.GetRequiredService<IConfigurationProtector>();
        string token = protector.Protect("di secret");
        Assert.Equal("di secret", protector.Unprotect(token));
    }

    [Fact]
    public void AddPostQuantumConfiguration_registers_a_singleton()
    {
        using PostQuantum.KeyManagement.Local.LocalContentKeyProvider keyProvider = TestKeys.NewProvider();

        ServiceProvider services = new ServiceCollection()
            .AddSingleton<IContentKeyProvider>(keyProvider)
            .AddPostQuantumConfiguration()
            .BuildServiceProvider();

        var first = services.GetRequiredService<IConfigurationProtector>();
        var second = services.GetRequiredService<IConfigurationProtector>();
        Assert.Same(first, second);
    }
}
