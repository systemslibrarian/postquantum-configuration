using PostQuantum.Configuration.Hybrid;
using PostQuantum.Configuration.Internal;
using Xunit;

namespace PostQuantum.Configuration.Tests;

public sealed class HybridKemTests
{
    [MLKemFact]
    public void Protect_then_Unprotect_roundtrips_through_the_hybrid_provider()
    {
        using var provider = HybridKemContentKeyProvider.Generate();
        var protector = new PostQuantumConfigProtector(provider);

        string token = protector.Protect("Server=db;Password=quantum-safe;");
        Assert.Equal("Server=db;Password=quantum-safe;", protector.Unprotect(token));
    }

    [MLKemFact]
    public void Provider_reports_its_hybrid_identity()
    {
        using var provider = HybridKemContentKeyProvider.Generate();
        Assert.Equal("hybrid-mlkem768-ecdhp256", provider.ProviderId);
        Assert.StartsWith("hk-", provider.ActiveKeyId);
        Assert.True(provider.CanUnwrap);
    }

    [MLKemFact]
    public void A_persisted_private_key_recovers_values_in_a_later_process()
    {
        string token;
        byte[] exportedPrivate;
        string keyId;

        using (var original = HybridKemContentKeyProvider.Generate())
        {
            keyId = original.ActiveKeyId;
            token = new PostQuantumConfigProtector(original).Protect("durable secret");
            exportedPrivate = original.ExportPrivateKey();
        }

        // Reconstruct from the exported private key (simulating a restart).
        using var restored = HybridKemContentKeyProvider.ImportPrivateKey(exportedPrivate);
        Assert.Equal(keyId, restored.ActiveKeyId); // same recipient fingerprint
        Assert.Equal("durable secret", new PostQuantumConfigProtector(restored).Unprotect(token));
    }

    [MLKemFact]
    public void A_public_only_provider_can_seal_but_not_open()
    {
        using var recipient = HybridKemContentKeyProvider.Generate();
        byte[] publicKey = recipient.ExportPublicKey();

        using var sealer = HybridKemContentKeyProvider.ImportPublicKey(publicKey);
        Assert.False(sealer.CanUnwrap);
        Assert.Equal(recipient.ActiveKeyId, sealer.ActiveKeyId);

        // The sender (public-only) seals…
        string token = new PostQuantumConfigProtector(sealer).Protect("for the recipient only");

        // …the sender cannot open it…
        Assert.Throws<InvalidOperationException>(() => new PostQuantumConfigProtector(sealer).Unprotect(token));

        // …but the recipient (private) can.
        Assert.Equal("for the recipient only", new PostQuantumConfigProtector(recipient).Unprotect(token));
    }

    [MLKemFact]
    public void Exporting_a_private_key_from_a_public_only_provider_is_rejected()
    {
        using var recipient = HybridKemContentKeyProvider.Generate();
        using var sealer = HybridKemContentKeyProvider.ImportPublicKey(recipient.ExportPublicKey());
        Assert.Throws<InvalidOperationException>(() => sealer.ExportPrivateKey());
    }

    [MLKemFact]
    public void A_different_recipient_cannot_unwrap_the_value()
    {
        using var alice = HybridKemContentKeyProvider.Generate();
        using var bob = HybridKemContentKeyProvider.Generate();

        string token = new PostQuantumConfigProtector(alice).Protect("alice's secret");

        // Bob's provider owns the same provider family but a different recipient key → unwrap fails.
        Assert.False(new PostQuantumConfigProtector(bob).TryUnprotect(token, out _));
    }

    [MLKemFact]
    public void Tampering_with_a_hybrid_token_is_detected()
    {
        using var provider = HybridKemContentKeyProvider.Generate();
        var protector = new PostQuantumConfigProtector(provider);

        string token = protector.Protect("a value worth protecting end to end");
        byte[] body = PortableEncoding.FromBase64Url(token.Substring("pqc.v1.".Length));
        body[^1] ^= 0xFF; // corrupt the last byte (inside the GCM-protected region)
        string tampered = "pqc.v1." + PortableEncoding.ToBase64Url(body);

        Assert.False(protector.TryUnprotect(tampered, out _));
    }

    [MLKemFact]
    public void Each_wrap_uses_a_fresh_ephemeral_so_tokens_differ()
    {
        using var provider = HybridKemContentKeyProvider.Generate();
        var protector = new PostQuantumConfigProtector(provider);

        string first = protector.Protect("same");
        string second = protector.Protect("same");
        Assert.NotEqual(first, second);
        Assert.Equal("same", protector.Unprotect(first));
        Assert.Equal("same", protector.Unprotect(second));
    }
}
