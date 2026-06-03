#if NET10_0_OR_GREATER
using System.IO;
using System.Security.Cryptography;
using PostQuantum.Configuration.Internal;
using PostQuantum.KeyManagement;

namespace PostQuantum.Configuration.Hybrid;

/// <summary>
/// An <see cref="IContentKeyProvider"/> whose key-encryption step is a <b>hybrid post-quantum KEM</b>:
/// each content key (data-encryption key) is wrapped to a recipient key pair using
/// <b>ML-KEM-768</b> (FIPS 203, the post-quantum half) <i>and</i> <b>ECDH P-256</b> (the classical
/// half), combined through HKDF-SHA256 and used to AES-256-GCM-seal the content key.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why hybrid.</b> The wrap remains secure unless <em>both</em> ML-KEM-768 and ECDH P-256 are
/// broken. ML-KEM provides the forward, post-quantum confidentiality (a “harvest now, decrypt later”
/// adversary with a future quantum computer still cannot recover the key); ECDH P-256 protects against
/// any undiscovered weakness in the newer ML-KEM. This is the same defence-in-depth philosophy as
/// <c>PostQuantum.Jwt</c>'s X-Wing, expressed with primitives that ship natively in the .NET BCL.
/// </para>
/// <para>
/// <b>Construction (per wrap).</b> A fresh ephemeral ECDH P-256 key pair is generated, and ML-KEM is
/// encapsulated to the recipient's encapsulation key. The two shared secrets are concatenated as HKDF
/// input keying material; the HKDF <c>info</c> binds the construction label, the recipient fingerprint,
/// the ML-KEM ciphertext, and the ephemeral ECDH public key (full transcript binding). The derived key
/// seals the content key with AES-256-GCM. The wrapped blob carries the ML-KEM ciphertext, the
/// ephemeral ECDH public key, the GCM nonce, the tag, and the sealed content key — everything needed to
/// recover it with the recipient's private key, and nothing secret beyond that.
/// </para>
/// <para>
/// <b>Honesty.</b> The combiner (concatenated shared secrets into HKDF, transcript-bound) follows the
/// well-trodden NIST SP 800-56C / IETF hybrid-KEM pattern, but this specific construction is
/// <b>not a standardised, named scheme and has not been independently audited.</b> The primitives are
/// the BCL's; the envelope and combiner are this library's. See <c>KNOWN-GAPS.md</c>.
/// </para>
/// <para>
/// <b>Availability.</b> Requires .NET 9+ and a platform where ML-KEM is available
/// (<see cref="MLKem.IsSupported"/> — on Linux, OpenSSL 3.5+). The factory methods throw
/// <see cref="PlatformNotSupportedException"/> where it is not.
/// </para>
/// </remarks>
public sealed class HybridKemContentKeyProvider : ContentKeyProvider, IDisposable
{
    /// <summary>The stable provider-family identifier recorded on every wrapped key.</summary>
    public const string Provider = "hybrid-mlkem768-ecdhp256";

    private const string Algorithm = "MLKEM768-ECDHP256-HKDF-SHA256-AESGCM256";
    private const string HkdfInfoLabel = "PostQuantum.Configuration/hybrid-kem/v1";
    private const byte BlobVersion = 1;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int SharedSecretSize = 32;

    private readonly MLKem _mlkem;            // full key when _hasPrivate, otherwise encapsulation-only
    private readonly ECDiffieHellman _ecdh;   // full key when _hasPrivate, otherwise public-only
    private readonly byte[] _mlkemEncapsulationKey; // non-secret recipient public material
    private readonly byte[] _ecdhPublicSpki;        // non-secret recipient public material
    private readonly bool _hasPrivate;
    private readonly string _activeKeyId;
    private bool _disposed;

    private HybridKemContentKeyProvider(MLKem mlkem, ECDiffieHellman ecdh, bool hasPrivate)
    {
        _mlkem = mlkem;
        _ecdh = ecdh;
        _hasPrivate = hasPrivate;
        _mlkemEncapsulationKey = mlkem.ExportEncapsulationKey();
        _ecdhPublicSpki = ecdh.PublicKey.ExportSubjectPublicKeyInfo();
        _activeKeyId = ComputeKeyId(_mlkemEncapsulationKey, _ecdhPublicSpki);
    }

    /// <inheritdoc />
    public override string ProviderId => Provider;

    /// <inheritdoc />
    public override string ActiveKeyId => _activeKeyId;

    /// <inheritdoc />
    protected override string WrapAlgorithm => Algorithm;

    /// <summary>Whether this instance holds the private key material required to unwrap (decrypt).</summary>
    public bool CanUnwrap => _hasPrivate;

    /// <summary>Generates a fresh recipient key pair (ML-KEM-768 + ECDH P-256) that can wrap and unwrap.</summary>
    /// <exception cref="PlatformNotSupportedException">ML-KEM is not available on this platform.</exception>
    public static HybridKemContentKeyProvider Generate()
    {
        EnsureSupported();
        MLKem mlkem = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
        ECDiffieHellman ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        return new HybridKemContentKeyProvider(mlkem, ecdh, hasPrivate: true);
    }

    /// <summary>
    /// Exports the recipient's <b>public</b> key material — safe to distribute to any party that should
    /// be able to protect values for this recipient. Pair with <see cref="ImportPublicKey"/>.
    /// </summary>
    public byte[] ExportPublicKey()
    {
        ThrowIfDisposed();
        using var buffer = new MemoryStream();
        PortableEncoding.WriteByte(buffer, BlobVersion);
        PortableEncoding.WriteBytes(buffer, _mlkemEncapsulationKey);
        PortableEncoding.WriteBytes(buffer, _ecdhPublicSpki);
        return buffer.ToArray();
    }

    /// <summary>
    /// Exports the recipient's <b>private</b> key material. <b>This is highly sensitive</b> — anyone
    /// holding it can decrypt every value protected for this recipient. Store it only in a secret
    /// manager / KMS / HSM, never in source control. Pair with <see cref="ImportPrivateKey"/>.
    /// </summary>
    public byte[] ExportPrivateKey()
    {
        ThrowIfDisposed();
        if (!_hasPrivate)
        {
            throw new InvalidOperationException("This is a public-only provider; it has no private key to export.");
        }

        byte[] mlkemDk = _mlkem.ExportDecapsulationKey();
        byte[] ecdhPkcs8 = _ecdh.ExportPkcs8PrivateKey();
        try
        {
            using var buffer = new MemoryStream();
            PortableEncoding.WriteByte(buffer, BlobVersion);
            PortableEncoding.WriteBytes(buffer, mlkemDk);
            PortableEncoding.WriteBytes(buffer, ecdhPkcs8);
            return buffer.ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(mlkemDk);
            CryptographicOperations.ZeroMemory(ecdhPkcs8);
        }
    }

    /// <summary>Reconstructs a <b>wrap-only</b> provider from public key material produced by <see cref="ExportPublicKey"/>.</summary>
    /// <exception cref="PlatformNotSupportedException">ML-KEM is not available on this platform.</exception>
    /// <exception cref="FormatException">The blob is malformed or uses an unsupported version.</exception>
    public static HybridKemContentKeyProvider ImportPublicKey(byte[] publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        EnsureSupported();

        (byte[] mlkemEk, byte[] ecdhSpki) = ParseKeyBlob(publicKey);
        MLKem mlkem = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, mlkemEk);
        var ecdh = ECDiffieHellman.Create();
        ecdh.ImportSubjectPublicKeyInfo(ecdhSpki, out _);
        return new HybridKemContentKeyProvider(mlkem, ecdh, hasPrivate: false);
    }

    /// <summary>Reconstructs a full (wrap + unwrap) provider from private key material produced by <see cref="ExportPrivateKey"/>.</summary>
    /// <exception cref="PlatformNotSupportedException">ML-KEM is not available on this platform.</exception>
    /// <exception cref="FormatException">The blob is malformed or uses an unsupported version.</exception>
    public static HybridKemContentKeyProvider ImportPrivateKey(byte[] privateKey)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        EnsureSupported();

        (byte[] mlkemDk, byte[] ecdhPkcs8) = ParseKeyBlob(privateKey);
        try
        {
            MLKem mlkem = MLKem.ImportDecapsulationKey(MLKemAlgorithm.MLKem768, mlkemDk);
            var ecdh = ECDiffieHellman.Create();
            ecdh.ImportPkcs8PrivateKey(ecdhPkcs8, out _);
            return new HybridKemContentKeyProvider(mlkem, ecdh, hasPrivate: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(mlkemDk);
            CryptographicOperations.ZeroMemory(ecdhPkcs8);
        }
    }

    /// <inheritdoc />
    protected override ValueTask<byte[]> WrapKeyAsync(string keyId, ReadOnlyMemory<byte> contentKey, CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        cancellationToken.ThrowIfCancellationRequested();

        // Post-quantum half: encapsulate to the recipient's ML-KEM key.
        _mlkem.Encapsulate(out byte[] mlkemCiphertext, out byte[] mlkemSharedSecret);

        // Classical half: ephemeral ECDH against the recipient's public key.
        using var ephemeral = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        byte[] ephemeralPublicSpki = ephemeral.PublicKey.ExportSubjectPublicKeyInfo();
        byte[] ecdhSharedSecret = ephemeral.DeriveRawSecretAgreement(_ecdh.PublicKey);

        byte[] wrapKey = DeriveWrapKey(mlkemSharedSecret, ecdhSharedSecret, mlkemCiphertext, ephemeralPublicSpki);
        CryptographicOperations.ZeroMemory(mlkemSharedSecret);
        CryptographicOperations.ZeroMemory(ecdhSharedSecret);

        var nonce = new byte[NonceSize];
        RandomNumberGenerator.Fill(nonce);
        var sealedKey = new byte[contentKey.Length];
        var tag = new byte[TagSize];

        try
        {
            using var aes = new AesGcm(wrapKey, TagSize);
            aes.Encrypt(nonce, contentKey.Span, sealedKey, tag);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrapKey);
        }

        using var blob = new MemoryStream();
        PortableEncoding.WriteByte(blob, BlobVersion);
        PortableEncoding.WriteBytes(blob, mlkemCiphertext);
        PortableEncoding.WriteBytes(blob, ephemeralPublicSpki);
        PortableEncoding.WriteBytes(blob, nonce);
        PortableEncoding.WriteBytes(blob, tag);
        PortableEncoding.WriteBytes(blob, sealedKey);
        return ValueTask.FromResult(blob.ToArray());
    }

    /// <inheritdoc />
    protected override ValueTask<byte[]> UnwrapKeyAsync(WrappedContentKey wrappedKey, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(wrappedKey);
        ThrowIfDisposed();
        cancellationToken.ThrowIfCancellationRequested();

        if (!_hasPrivate)
        {
            throw new InvalidOperationException(
                "This is a public-only (wrap-only) provider and cannot unwrap. Import the private key to decrypt.");
        }

        byte[] data = wrappedKey.Ciphertext;
        int offset = 0;
        byte version = PortableEncoding.ReadByte(data, ref offset);
        if (version != BlobVersion)
        {
            throw new ConfigurationProtectionException("Unsupported hybrid-KEM wrapped-key version.");
        }

        byte[] mlkemCiphertext = PortableEncoding.ReadBytes(data, ref offset);
        byte[] ephemeralPublicSpki = PortableEncoding.ReadBytes(data, ref offset);
        byte[] nonce = PortableEncoding.ReadBytes(data, ref offset);
        byte[] tag = PortableEncoding.ReadBytes(data, ref offset);
        byte[] sealedKey = PortableEncoding.ReadBytes(data, ref offset);

        // Recover both shared secrets with the recipient's private keys.
        byte[] mlkemSharedSecret = _mlkem.Decapsulate(mlkemCiphertext);

        using var ephemeralPublic = ECDiffieHellman.Create();
        ephemeralPublic.ImportSubjectPublicKeyInfo(ephemeralPublicSpki, out _);
        byte[] ecdhSharedSecret = _ecdh.DeriveRawSecretAgreement(ephemeralPublic.PublicKey);

        byte[] wrapKey = DeriveWrapKey(mlkemSharedSecret, ecdhSharedSecret, mlkemCiphertext, ephemeralPublicSpki);
        CryptographicOperations.ZeroMemory(mlkemSharedSecret);
        CryptographicOperations.ZeroMemory(ecdhSharedSecret);

        var contentKey = new byte[sealedKey.Length];
        try
        {
            using var aes = new AesGcm(wrapKey, TagSize);
            aes.Decrypt(nonce, sealedKey, tag, contentKey);
            return ValueTask.FromResult(contentKey);
        }
        catch (CryptographicException ex)
        {
            CryptographicOperations.ZeroMemory(contentKey);
            throw new ConfigurationProtectionException(
                "The hybrid-KEM wrapped key failed authentication and could not be unwrapped.", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrapKey);
        }
    }

    private static byte[] DeriveWrapKey(
        byte[] mlkemSharedSecret,
        byte[] ecdhSharedSecret,
        byte[] mlkemCiphertext,
        byte[] ephemeralPublicSpki)
    {
        // IKM = ML-KEM shared secret || ECDH shared secret (both halves must be broken to recover it).
        var ikm = new byte[mlkemSharedSecret.Length + ecdhSharedSecret.Length];
        try
        {
            Buffer.BlockCopy(mlkemSharedSecret, 0, ikm, 0, mlkemSharedSecret.Length);
            Buffer.BlockCopy(ecdhSharedSecret, 0, ikm, mlkemSharedSecret.Length, ecdhSharedSecret.Length);

            // info binds the label, the ML-KEM ciphertext, and the ephemeral ECDH public — full transcript.
            using var info = new MemoryStream();
            PortableEncoding.WriteBytes(info, System.Text.Encoding.UTF8.GetBytes(HkdfInfoLabel));
            PortableEncoding.WriteBytes(info, mlkemCiphertext);
            PortableEncoding.WriteBytes(info, ephemeralPublicSpki);

            return HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, SharedSecretSize, salt: null, info.ToArray());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ikm);
        }
    }

    private static string ComputeKeyId(byte[] mlkemEncapsulationKey, byte[] ecdhPublicSpki)
    {
        // Domain-separated fingerprint of the recipient's public identity.
        var material = new byte[mlkemEncapsulationKey.Length + ecdhPublicSpki.Length];
        Buffer.BlockCopy(mlkemEncapsulationKey, 0, material, 0, mlkemEncapsulationKey.Length);
        Buffer.BlockCopy(ecdhPublicSpki, 0, material, mlkemEncapsulationKey.Length, ecdhPublicSpki.Length);
        byte[] hash = SHA256.HashData(material);
        return "hk-" + Convert.ToHexStringLower(hash.AsSpan(0, 8));
    }

    private static (byte[] First, byte[] Second) ParseKeyBlob(byte[] blob)
    {
        int offset = 0;
        byte version = PortableEncoding.ReadByte(blob, ref offset);
        if (version != BlobVersion)
        {
            throw new FormatException("Unsupported hybrid-KEM key blob version.");
        }

        byte[] first = PortableEncoding.ReadBytes(blob, ref offset);
        byte[] second = PortableEncoding.ReadBytes(blob, ref offset);
        return (first, second);
    }

    private static void EnsureSupported()
    {
        if (!MLKem.IsSupported)
        {
            throw new PlatformNotSupportedException(
                "ML-KEM is not available on this platform. The hybrid provider requires .NET 9+ with " +
                "ML-KEM support (on Linux, OpenSSL 3.5 or later).");
        }
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);

    /// <summary>Disposes the underlying ML-KEM and ECDH keys, releasing their (possibly private) material.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _mlkem.Dispose();
        _ecdh.Dispose();
    }
}
#endif
