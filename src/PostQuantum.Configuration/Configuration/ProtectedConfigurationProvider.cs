using System.Collections.Concurrent;
using System.Collections.Generic;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Primitives;

namespace PostQuantum.Configuration;

/// <summary>
/// An <see cref="IConfigurationProvider"/> that decorates another provider, transparently decrypting any
/// value that is a protected token (<c>pqc.v1.</c>) when it is read. Non-protected values pass straight
/// through untouched, so this layer is safe to wrap around a source that mixes plaintext and ciphertext.
/// </summary>
/// <remarks>
/// <para>
/// Decryption is lazy and memoised per key. The first read of a protected value unwraps it; subsequent
/// reads return the cached plaintext. When the inner provider signals a reload, the cache is cleared so
/// rotated or edited values are re-read.
/// </para>
/// <para>
/// The protector is resolved lazily through a factory, not captured at construction, because in a typical
/// host the protector depends on a passphrase that is itself supplied by earlier configuration or the
/// environment and is not available when the configuration pipeline is being assembled.
/// </para>
/// </remarks>
internal sealed class ProtectedConfigurationProvider : IConfigurationProvider, IDisposable
{
    private readonly IConfigurationProvider _inner;
    private readonly Func<IConfigurationProtector> _protectorFactory;
    private readonly bool _bindKeyAsContext;
    private readonly ConcurrentDictionary<string, string?> _decrypted = new(StringComparer.OrdinalIgnoreCase);
    private readonly IDisposable? _reloadRegistration;
    private IConfigurationProtector? _protector;

    internal ProtectedConfigurationProvider(
        IConfigurationProvider inner,
        Func<IConfigurationProtector> protectorFactory,
        bool bindKeyAsContext)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _protectorFactory = protectorFactory ?? throw new ArgumentNullException(nameof(protectorFactory));
        _bindKeyAsContext = bindKeyAsContext;

        // Drop cached plaintext whenever the underlying source reloads (file edit, etc.).
        _reloadRegistration = ChangeToken.OnChange(_inner.GetReloadToken, _decrypted.Clear);
    }

    /// <inheritdoc />
    public bool TryGet(string key, out string? value)
    {
        if (!_inner.TryGet(key, out string? raw))
        {
            value = null;
            return false;
        }

        if (!ProtectedValue.HasPrefix(raw))
        {
            value = raw;
            return true;
        }

        value = _decrypted.GetOrAdd(key, static (k, state) =>
        {
            IConfigurationProtector protector = state.self._protector ??= state.self._protectorFactory();
            string? context = state.self._bindKeyAsContext ? k : null;
            return protector.Unprotect(state.raw!, context);
        }, (self: this, raw));

        return true;
    }

    /// <inheritdoc />
    public void Set(string key, string? value) => _inner.Set(key, value);

    /// <inheritdoc />
    public IChangeToken GetReloadToken() => _inner.GetReloadToken();

    /// <inheritdoc />
    public void Load()
    {
        _inner.Load();
        _decrypted.Clear();
    }

    /// <inheritdoc />
    public IEnumerable<string> GetChildKeys(IEnumerable<string> earlierKeys, string? parentPath) =>
        _inner.GetChildKeys(earlierKeys, parentPath);

    /// <inheritdoc />
    public void Dispose()
    {
        _reloadRegistration?.Dispose();
        (_inner as IDisposable)?.Dispose();
    }
}
