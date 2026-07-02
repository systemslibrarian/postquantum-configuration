using System.Text;
using PostQuantum.KeyManagement.Local;
using Xunit;

namespace PostQuantum.Configuration.Tests;

/// <summary>
/// <see cref="ProtectedTokenInfo"/>: keyless inspection surfaces routing metadata (and nothing more),
/// never throws on hostile input, and never implies authenticity.
/// </summary>
public class ProtectedTokenInfoTests
{
    [Fact]
    public void TryInspect_WellFormedToken_SurfacesEnvelopeMetadata()
    {
        (IConfigurationProtector protector, LocalContentKeyProvider provider) = TestKeys.NewProtector();
        using (provider)
        {
            const string plaintext = "Host=db;Password=s3cr3t";
            string token = protector.Protect(plaintext);

            Assert.True(ProtectedTokenInfo.TryInspect(token, out ProtectedTokenInfo? info));
            Assert.Equal(1, info!.FormatVersion);
            Assert.False(string.IsNullOrEmpty(info.ProviderId));
            Assert.False(string.IsNullOrEmpty(info.KeyId));
            Assert.False(string.IsNullOrEmpty(info.WrapAlgorithm));
            Assert.Equal(Encoding.UTF8.GetByteCount(plaintext), info.CiphertextLength);
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("plaintext, not a token")]
    [InlineData("pqc.v1.")]
    [InlineData("pqc.v1.!!!not-base64url!!!")]
    [InlineData("pqc.v2.AQAA")] // unknown prefix version — never guessed
    public void TryInspect_HostileOrForeignInput_ReturnsFalseWithoutThrowing(string? input)
    {
        Assert.False(ProtectedTokenInfo.TryInspect(input, out ProtectedTokenInfo? info));
        Assert.Null(info);
    }

    [Fact]
    public void TryInspect_WellFormedDoesNotMeanDecryptable()
    {
        (IConfigurationProtector protector, LocalContentKeyProvider provider) = TestKeys.NewProtector();
        using (provider)
        {
            // Sealed under a context: structurally valid to anyone, decryptable only with the context.
            string token = protector.Protect("secret", context: "ConnectionStrings:Primary");

            Assert.True(ProtectedTokenInfo.TryInspect(token, out _));
            Assert.False(protector.TryUnprotect(token, out _)); // no context → fails closed
        }
    }

    [Fact]
    public void KeyId_TracksRotation_SoStaleTokensAreFindable()
    {
        (IConfigurationProtector protector, LocalContentKeyProvider provider) = TestKeys.NewProtector();
        using (provider)
        {
            string oldToken = protector.Protect("secret");
            Assert.True(ProtectedTokenInfo.TryInspect(oldToken, out ProtectedTokenInfo? oldInfo));

            string newActiveKeyId = provider.Rotate(TestKeys.Passphrase, LocalKekOptions.LowMemory);
            string reSealed = protector.Reprotect(oldToken);
            Assert.True(ProtectedTokenInfo.TryInspect(reSealed, out ProtectedTokenInfo? newInfo));

            // The stale token still names the retired KEK; the re-sealed one names the active KEK.
            Assert.NotEqual(oldInfo!.KeyId, newInfo!.KeyId);
            Assert.Equal(newActiveKeyId, newInfo.KeyId);
        }
    }
}
