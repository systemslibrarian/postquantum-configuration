using Microsoft.Extensions.Configuration;

namespace PostQuantum.Configuration;

/// <summary>
/// An <see cref="IConfigurationSource"/> that wraps another source so that protected (<c>pqc.v1.</c>)
/// values it produces are transparently decrypted when read. Add it to a configuration builder via the
/// <c>AddEncrypted</c> extension methods.
/// </summary>
public sealed class ProtectedConfigurationSource : IConfigurationSource
{
    /// <summary>The underlying source whose values may contain protected tokens.</summary>
    public required IConfigurationSource Inner { get; init; }

    /// <summary>
    /// Factory that supplies the <see cref="IConfigurationProtector"/> used to decrypt. Invoked lazily,
    /// the first time a protected value is read, so the protector may depend on configuration loaded
    /// earlier in the pipeline.
    /// </summary>
    public required Func<IConfigurationProtector> ProtectorFactory { get; init; }

    /// <summary>
    /// When <see langword="true"/>, each value's configuration key is bound into the decryption context,
    /// so a token only decrypts under the key it was sealed for. Values protected for transparent use
    /// must then be sealed with that same key as their context. Defaults to <see langword="false"/>.
    /// </summary>
    public bool BindKeyAsContext { get; init; }

    /// <inheritdoc />
    public IConfigurationProvider Build(IConfigurationBuilder builder) =>
        new ProtectedConfigurationProvider(Inner.Build(builder), ProtectorFactory, BindKeyAsContext);
}
