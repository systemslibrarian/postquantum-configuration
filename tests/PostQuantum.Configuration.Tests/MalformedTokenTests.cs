using Xunit;

namespace PostQuantum.Configuration.Tests;

public sealed class MalformedTokenTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not a token")]
    [InlineData("ConnectionStrings:Default")]
    [InlineData("pqc.v2.abc")]            // unsupported version prefix
    [InlineData("pqc.v1.")]              // prefix but empty body
    [InlineData("pqc.v1.!!!not base64!!!")]
    [InlineData("pqc.v1.AAAA")]          // valid base64, but truncated framing
    public void TryUnprotect_returns_false_for_malformed_input(string? token)
    {
        var (protector, provider) = TestKeys.NewProtector();
        using (provider)
        {
            Assert.False(protector.TryUnprotect(token!, out string? plaintext));
            Assert.Null(plaintext);
        }
    }

    [Theory]
    [InlineData("")]
    [InlineData("not a token")]
    [InlineData("pqc.v1.AAAA")]
    public void Unprotect_throws_a_ConfigurationProtectionException_for_malformed_input(string token)
    {
        var (protector, provider) = TestKeys.NewProtector();
        using (provider)
        {
            Assert.Throws<ConfigurationProtectionException>(() => protector.Unprotect(token));
        }
    }

    [Fact]
    public void Protect_rejects_a_null_plaintext()
    {
        var (protector, provider) = TestKeys.NewProtector();
        using (provider)
        {
            Assert.Throws<ArgumentNullException>(() => protector.Protect(null!));
        }
    }

    [Fact]
    public void The_protector_rejects_a_null_key_provider()
    {
        Assert.Throws<ArgumentNullException>(() => new PostQuantumConfigProtector(null!));
    }
}
