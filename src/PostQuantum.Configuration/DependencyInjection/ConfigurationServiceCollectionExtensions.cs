using Microsoft.Extensions.DependencyInjection.Extensions;
using PostQuantum.Configuration;
using PostQuantum.KeyManagement;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// <see cref="IServiceCollection"/> extensions that register the configuration protector.
/// </summary>
public static class ConfigurationServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="IConfigurationProtector"/> (implemented by
    /// <see cref="PostQuantumConfigProtector"/>) as a singleton over the host's registered
    /// <see cref="IContentKeyProvider"/>.
    /// </summary>
    /// <remarks>
    /// An <see cref="IContentKeyProvider"/> must already be registered — typically by calling
    /// <c>AddPostQuantumKeyManagement</c> from <c>PostQuantum.KeyManagement</c> first. This method does
    /// not register a key provider itself, so key custody and rotation policy stay explicit and in one
    /// place.
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is <see langword="null"/>.</exception>
    public static IServiceCollection AddPostQuantumConfiguration(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddSingleton<IConfigurationProtector, PostQuantumConfigProtector>();
        return services;
    }
}
