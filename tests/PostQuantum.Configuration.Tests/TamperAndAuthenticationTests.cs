using System.Text;
using PostQuantum.Configuration.Internal;
using Xunit;

namespace PostQuantum.Configuration.Tests;

public sealed class TamperAndAuthenticationTests
{
    private static string FlipOneBodyByte(string token, int bodyByteIndex)
    {
        string body = token.Substring("pqc.v1.".Length);
        byte[] bytes = PortableEncoding.FromBase64Url(body);
        bytes[bodyByteIndex] ^= 0xFF;
        return "pqc.v1." + PortableEncoding.ToBase64Url(bytes);
    }

    [Fact]
    public void A_flipped_ciphertext_byte_fails_authentication()
    {
        var (protector, provider) = TestKeys.NewProtector();
        using (provider)
        {
            string token = protector.Protect("a value long enough to have body bytes to corrupt");

            // Corrupt a byte near the end of the body (inside ciphertext/tag region).
            string tampered = FlipOneBodyByte(token, PortableEncoding.FromBase64Url(token.Substring(7)).Length - 4);

            Assert.Throws<ConfigurationProtectionException>(() => protector.Unprotect(tampered));
            Assert.False(protector.TryUnprotect(tampered, out _));
        }
    }

    [Fact]
    public void Every_single_byte_corruption_in_the_body_is_rejected()
    {
        var (protector, provider) = TestKeys.NewProtector();
        using (provider)
        {
            string token = protector.Protect("secret");
            byte[] body = PortableEncoding.FromBase64Url(token.Substring(7));

            int accepted = 0;
            for (int i = 0; i < body.Length; i++)
            {
                string tampered = FlipOneBodyByte(token, i);
                if (protector.TryUnprotect(tampered, out string? recovered) && recovered == "secret")
                {
                    accepted++;
                }
            }

            // No single-byte corruption may ever decrypt back to the original plaintext.
            Assert.Equal(0, accepted);
        }
    }

    [Fact]
    public void A_token_from_a_different_passphrase_does_not_decrypt()
    {
        var (alice, aliceProvider) = TestKeys.NewProtector("alice's passphrase");
        var (bob, bobProvider) = TestKeys.NewProtector("bob's different passphrase");
        using (aliceProvider)
        using (bobProvider)
        {
            string token = alice.Protect("alice's secret");
            Assert.False(bob.TryUnprotect(token, out _));
        }
    }

    [Fact]
    public void Context_must_match_between_protect_and_unprotect()
    {
        var (protector, provider) = TestKeys.NewProtector();
        using (provider)
        {
            string token = protector.Protect("db password", context: "ConnectionStrings:Primary");

            Assert.Equal("db password", protector.Unprotect(token, context: "ConnectionStrings:Primary"));
            Assert.Throws<ConfigurationProtectionException>(() => protector.Unprotect(token, context: "ConnectionStrings:Replica"));
            Assert.Throws<ConfigurationProtectionException>(() => protector.Unprotect(token, context: null));
        }
    }

    [Fact]
    public void A_value_sealed_without_context_does_not_open_with_one()
    {
        var (protector, provider) = TestKeys.NewProtector();
        using (provider)
        {
            string token = protector.Protect("no-context secret");
            Assert.Throws<ConfigurationProtectionException>(() => protector.Unprotect(token, context: "unexpected"));
        }
    }
}
