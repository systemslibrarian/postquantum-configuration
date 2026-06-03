# Known gaps

What `PostQuantum.Configuration` deliberately does **not** do yet, stated plainly. We would rather you
know the limits up front than discover them in production. Each gap links to the roadmap item that would
close it.

---

## 1. The "post-quantum" claim depends on which provider you use

With the **default** (symmetric) key provider, the only post-quantum property is
**symmetric-by-key-size**: AES-256-GCM and Argon2id retain useful margin against a quantum adversary
because Grover's algorithm only *halves* their effective strength (AES-256 ≈ 128-bit post-quantum). No
asymmetric KEM is involved.

As of 0.2 there **is** an optional hybrid provider (`HybridKemContentKeyProvider`) that adds true
post-quantum **asymmetric** key wrapping with ML-KEM-768 + ECDH P-256. **But** (a) it requires .NET 10 +
ML-KEM (OpenSSL 3.5+ on Linux), and (b) the combiner — while built from the standard
concatenate-into-HKDF, transcript-bound pattern — is **not a named standard and has not been
independently audited** (see §6).

**Impact:** describe deployments to match the provider you actually run. The default provider is not
"quantum-safe key exchange"; the hybrid provider is post-quantum key exchange but unaudited.

**Closing it fully:** roadmap — external review of the combiner, and alignment with a standardised
hybrid KEM (e.g. IETF X-Wing) once one stabilises in the BCL.

## 2. The default return type is still an immutable `string`

`Unprotect` returns `string`, which the CLR cannot reliably zero — a decrypted secret may linger on the
managed heap until GC (and possibly in a swap file or crash dump).

As of 0.2, `UnprotectToSecret` returns a `Secret` that holds the plaintext in a buffer it zeroes on
dispose, and `Reprotect` uses that path internally. The intermediate byte buffers in encrypt/decrypt are
zeroed, and `ContentKey` zeroes its key material. **But** `Secret.Reveal()` and the convenience `string`
APIs still produce immutable strings, and `Secret` is a mitigation, not a guarantee (GC compaction can
still copy buffers).

**Impact:** byte-friendly code can now minimise plaintext lifetime; code that must hand a `string` to
another API still can't fully control it. This library is still not a substitute for OS-level secret
protection against an attacker who can read your process memory.

**Closing it fully:** bounded by the platform — there is no perfectly zeroable managed `string`.

## 3. ~~No built-in CLI~~ — done in 0.2

The `pqc-config` tool (`PostQuantum.Configuration.Tool`) ships `protect` / `unprotect` / `rotate`.
*Remaining nuance:* the CLI uses a single-passphrase keyring, so `rotate` rotates the key under the same
passphrase (changing the passphrase outright while keeping old tokens openable needs multi-passphrase
resolution, which the simple CLI does not do).

## 4. ~~No bulk re-seal helper~~ — done in 0.2

`Reprotect(token)` and `ReprotectAllAsync(IDictionary<string,string?>)` re-seal values under the active
key after a rotation. *Remaining nuance:* `ReprotectAllAsync` operates on a mutable dictionary you load
and persist yourself; it does not write back to a live `IConfigurationProvider`.

## 5. Context binding is opt-in, not on by default

The transparent configuration layer does **not** bind the configuration key as context by default
(`bindKeyAsContext: false`). This is a deliberate least-surprise choice — it means a token decrypts
regardless of which key it sits under, so moving a value between keys “just works.” The cost is that, by
default, a token is **not** bound to its slot and could be swapped.

**Impact:** if you want swap resistance, you must opt in (`bindKeyAsContext: true`) and seal values with
their key as context. Mixing bound and unbound tokens under transparent reads will fail closed for the
mismatched ones (by design).

**Closing it:** documented; may become a recommended default in a future major version.

## 6. Not independently audited

No third party has reviewed this code, its envelope construction, or the hybrid ML-KEM + ECDH combiner.
The cryptographic primitives are the .NET BCL's and `PostQuantum.KeyManagement`'s — not re-implemented
here — which limits the blast radius, but the framing, token format, hybrid combiner, and integration
logic are unreviewed. An internal [self-review checklist](docs/security-review-checklist.md) is run each
release; that is not a substitute for external audit.

**Closing it:** roadmap item — external review before a stable `1.0`.

## 7. Supply-chain provenance: code-signing still missing

Deterministic builds, SourceLink, symbol packages, a CycloneDX SBOM, and — as of 0.2 — a
**build-provenance attestation** (`actions/attest-build-provenance`) in the release workflow are in
place. **An author code-signing certificate is still not present** — see
[`docs/supply-chain.md`](docs/supply-chain.md) for exactly what is and isn't present.

## 8. Preview stability

The public API and the `pqc.v1` token format are **not frozen**. A future preview may change either.
When the token format changes, the prefix version (`pqc.v1.`) will change with it so old and new tokens
are distinguishable, but cross-version readers are not guaranteed before `1.0`.

---

*If a gap here is a blocker for you, please open an issue — it helps prioritise the roadmap.*
