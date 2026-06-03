using System.Text;
using Xunit;

namespace PostQuantum.Configuration.Tests;

public sealed class SecretTests
{
    [Fact]
    public void UnprotectToSecret_recovers_the_value_as_bytes()
    {
        var (protector, provider) = TestKeys.NewProtector();
        using (provider)
        {
            string token = protector.Protect("Server=db;Password=p@ss;");
            using Secret secret = protector.UnprotectToSecret(token);

            Assert.Equal("Server=db;Password=p@ss;", Encoding.UTF8.GetString(secret.Bytes));
            Assert.Equal("Server=db;Password=p@ss;", secret.Reveal());
            Assert.Equal(Encoding.UTF8.GetByteCount("Server=db;Password=p@ss;"), secret.Length);
        }
    }

    [Fact]
    public void UnprotectToSecret_honours_context_binding()
    {
        var (protector, provider) = TestKeys.NewProtector();
        using (provider)
        {
            string token = protector.Protect("secret", context: "slot-A");
            using Secret ok = protector.UnprotectToSecret(token, context: "slot-A");
            Assert.Equal("secret", ok.Reveal());

            Assert.Throws<ConfigurationProtectionException>(() => protector.UnprotectToSecret(token, context: "slot-B"));
        }
    }

    [Fact]
    public void Disposing_a_secret_zeroes_and_blocks_further_access()
    {
        var secret = new Secret(Encoding.UTF8.GetBytes("top-secret"));
        Assert.Equal("top-secret", secret.Reveal());

        secret.Dispose();

        Assert.Throws<ObjectDisposedException>(() => _ = secret.Bytes.Length);
        Assert.Throws<ObjectDisposedException>(() => secret.Reveal());
        Assert.Throws<ObjectDisposedException>(() => _ = secret.Length);
        Assert.Equal("Secret(disposed)", secret.ToString());

        // Dispose is idempotent.
        secret.Dispose();
    }

    [Fact]
    public void Secret_redacts_its_contents_in_ToString()
    {
        using var secret = new Secret(Encoding.UTF8.GetBytes("super-secret-value"));
        Assert.DoesNotContain("super-secret", secret.ToString());
        Assert.Contains("bytes", secret.ToString());
    }

    [Fact]
    public void Secret_rejects_a_null_buffer()
    {
        Assert.Throws<ArgumentNullException>(() => new Secret(null!));
    }
}
