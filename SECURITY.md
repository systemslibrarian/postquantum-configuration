# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Use GitHub's **“Report a vulnerability”** button on the repository
(`Security` → `Report a vulnerability`), or email the maintainer privately. Include:

- a description of the issue and its impact,
- the version (`0.1.0-preview.1`, commit if building from source),
- a minimal reproduction if you have one.

You will get an acknowledgement, and a fix or mitigation plan once the report is triaged. Please give a
reasonable window to respond before any public disclosure.

## Supported versions

This project is in preview. Only the **latest `0.x` preview** receives security fixes. There are no
backports to earlier previews.

| Version | Supported |
|---|---|
| `0.1.0-preview.*` (latest) | ✅ |
| anything older | ❌ |

## What this library protects — and what it relies on

`PostQuantum.Configuration` seals configuration values with **AES-256-GCM** under a fresh 256-bit
content key per value. The content key is wrapped by a key-encryption key (KEK) owned by an
`IContentKeyProvider` from [`PostQuantum.KeyManagement`](https://github.com/systemslibrarian/PostQuantum.KeyManagement).
**All confidentiality ultimately rests on that KEK.** This library does not invent cryptography; it
writes the envelope and the token framing.

### Scope of the “post-quantum” claim

With the **default** (symmetric) key provider, the post-quantum property is **symmetric-by-key-size**:
AES-256-GCM and Argon2id retain useful margin against a quantum adversary because Grover's algorithm only
halves their effective strength. No asymmetric KEM is involved — do not call it “quantum-safe key
exchange.”

The optional **`HybridKemContentKeyProvider`** (0.2+) adds post-quantum **asymmetric** key wrapping:
each content key is wrapped with **ML-KEM-768** (FIPS 203) **and** **ECDH P-256**, combined through
HKDF-SHA256 and AES-256-GCM, so the wrap survives unless *both* are broken. The primitives are the .NET
BCL's; the combiner follows the standard concatenate-into-HKDF, transcript-bound pattern but is **not a
named standard and has not been independently audited.** It requires .NET 10 + ML-KEM (OpenSSL 3.5+ on
Linux). See [`KNOWN-GAPS.md`](KNOWN-GAPS.md) and [`docs/threat-model.md`](docs/threat-model.md).

## Security properties (invariants)

1. **Authenticated encryption.** Every value is AES-256-GCM sealed. Any single-byte corruption of a
   token is detected and rejected — there is no path that returns attacker-influenced plaintext.
2. **Fresh randomness per value.** A new content key and a new 96-bit nonce are generated for every
   `Protect`. Identical plaintexts produce different tokens.
3. **Fail-closed and opaque.** Malformed token, tampered ciphertext, wrong key, and wrong context all
   collapse to one `ConfigurationProtectionException` (or `TryUnprotect == false`). The message never
   reveals which failure occurred.
4. **Hostile-input resistance.** Token decoding uses overflow-safe length arithmetic and caps every
   field at 1 MiB. `TryUnprotect` never throws on malformed input.
5. **Context integrity (opt-in).** When a context is supplied, it is bound into the GCM additional
   authenticated data, so a token sealed for one slot cannot be unsealed for another.

## Recommended production configuration

- **Passphrase / KEK custody.** Supply the passphrase from a secret store or environment variable —
  **never** from a checked-in configuration file. The committed token in the `WebApi` sample uses a
  clearly-labelled *dev-only* passphrase; do not copy that pattern to production.
- **Argon2id work factor.** When deriving a local KEK, prefer at least the `Interactive` preset
  (RFC 9106 §4 “second recommended”: 64 MiB / 3 / 4); use `Moderate` or `Sensitive` for long-lived,
  high-value secrets. The work factor is your defence against offline guessing of a leaked keyring.
  See [`PostQuantum.KeyManagement`'s `SECURITY.md`](https://github.com/systemslibrarian/PostQuantum.KeyManagement)
  for the recommended production profile.
- **Keyring durability.** Persist the keyring (`KeyringPath` / `FileKeyringStore`) so KEKs survive
  restarts; the keyring blob is non-secret but must be durable.
- **Rotate keys** periodically and after any suspected exposure. Old tokens keep opening; re-seal
  high-value values under the new KEK.
- **Don't log recovered plaintext.** The records in this library and `PostQuantum.KeyManagement` redact
  byte content in `ToString()`, but your own code must avoid logging decrypted values.

## Cryptographic dependencies

| Primitive | Source |
|---|---|
| AES-256-GCM (value encryption) | .NET BCL `System.Security.Cryptography.AesGcm` |
| Argon2id (KEK derivation) | `PostQuantum.KeyManagement` (via `Konscious.Security.Cryptography.Argon2`) |
| Content-key generation, wrapping, rotation | `PostQuantum.KeyManagement` |
| ML-KEM-768 (hybrid provider) | .NET BCL `System.Security.Cryptography.MLKem` (FIPS 203) |
| ECDH P-256, HKDF-SHA256 (hybrid provider) | .NET BCL `System.Security.Cryptography` |

No cryptographic primitive is implemented in this repository; the hybrid provider only **combines** BCL
primitives (concatenated shared secrets into HKDF, transcript-bound).
