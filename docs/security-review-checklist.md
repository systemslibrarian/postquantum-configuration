# Security self-review checklist

This is the **internal** review the maintainer runs before a release. It is **not** an external audit —
no third party has reviewed this code (see [`KNOWN-GAPS.md` §6](../KNOWN-GAPS.md)). It exists so the
review is repeatable and its scope is transparent.

## Cryptographic construction

- [x] No cryptographic primitive is implemented in this repository; all come from the .NET BCL or
      `PostQuantum.KeyManagement`.
- [x] Value encryption is AES-256-GCM with a 96-bit random nonce and a fresh 256-bit content key **per
      value** (no nonce reuse across values under a shared key).
- [x] The hybrid provider concatenates the ML-KEM-768 and ECDH P-256 shared secrets as HKDF input and
      binds the full transcript (label, ML-KEM ciphertext, ephemeral ECDH public) in HKDF `info`.
- [x] All shared secrets, IKM, and derived wrap keys are zeroed after use
      (`CryptographicOperations.ZeroMemory`).
- [x] AES-GCM authentication failures are caught and surfaced opaquely; no partial/garbage plaintext is
      ever returned.

## Token / wire format

- [x] Every length-prefixed field is read with overflow-safe arithmetic (`length > available`, never
      `offset + length > total`).
- [x] Every field is capped (1 MiB) and the decoder rejects trailing bytes and wrong fixed sizes
      (nonce/tag).
- [x] Unknown format versions are rejected, not guessed.
- [x] `TryDecode` / `TryUnprotect` never throw on hostile input.

## API behaviour

- [x] Malformed / tampered / wrong-key / wrong-context all collapse to one opaque failure type.
- [x] Error messages never distinguish failure modes or echo secret material.
- [x] Records/types that hold bytes redact them in `ToString()`.
- [x] `Secret` zeroes on dispose and blocks access afterwards.

## Tests

- [x] Roundtrips across value shapes (empty, unicode, large, JSON).
- [x] Every single-byte corruption of a token is rejected.
- [x] Cross-key / cross-recipient isolation.
- [x] Context binding enforced both directions.
- [x] Hybrid path exercised on an ML-KEM-capable host (skips with a clear reason elsewhere).
- [x] Encoder overflow/negative/oversized-length rejection.

## Build / supply chain

- [x] Zero-warning build (warnings as errors).
- [x] Deterministic build, SourceLink, symbols, SBOM.
- [x] Build-provenance attestation in the release workflow.
- [ ] Author code-signing certificate — **not yet**.
- [ ] External security audit — **not yet**.
