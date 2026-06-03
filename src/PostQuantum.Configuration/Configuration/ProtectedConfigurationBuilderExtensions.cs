using Microsoft.Extensions.Configuration;

namespace PostQuantum.Configuration;

/// <summary>
/// <see cref="IConfigurationBuilder"/> extensions that wrap a configuration source so its protected
/// values are decrypted transparently on read.
/// </summary>
public static class ProtectedConfigurationBuilderExtensions
{
    /// <summary>
    /// Wraps <paramref name="inner"/> so that any <c>pqc.v1.</c> token it produces is decrypted on read
    /// using the protector returned by <paramref name="protectorFactory"/>.
    /// </summary>
    /// <param name="builder">The configuration builder.</param>
    /// <param name="inner">The source whose values may contain protected tokens.</param>
    /// <param name="protectorFactory">
    /// Lazily invoked to obtain the protector. Deferring resolution lets the protector depend on
    /// configuration (such as a passphrase) added earlier in the pipeline.
    /// </param>
    /// <param name="bindKeyAsContext">
    /// When <see langword="true"/>, binds each value's configuration key into the decryption context.
    /// </param>
    public static IConfigurationBuilder AddEncrypted(
        this IConfigurationBuilder builder,
        IConfigurationSource inner,
        Func<IConfigurationProtector> protectorFactory,
        bool bindKeyAsContext = false)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentNullException.ThrowIfNull(protectorFactory);

        builder.Add(new ProtectedConfigurationSource
        {
            Inner = inner,
            ProtectorFactory = protectorFactory,
            BindKeyAsContext = bindKeyAsContext,
        });
        return builder;
    }

    /// <summary>
    /// Wraps <paramref name="inner"/> with a protector instance that is already available.
    /// </summary>
    public static IConfigurationBuilder AddEncrypted(
        this IConfigurationBuilder builder,
        IConfigurationSource inner,
        IConfigurationProtector protector,
        bool bindKeyAsContext = false)
    {
        ArgumentNullException.ThrowIfNull(protector);
        return builder.AddEncrypted(inner, () => protector, bindKeyAsContext);
    }
}
