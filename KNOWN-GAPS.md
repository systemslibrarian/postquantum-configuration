# Known gaps

What `PostQuantum.Configuration` deliberately does **not** do yet, stated plainly. We would rather you
know the limits up front than discover them in production. Each gap links to the roadmap item that would
close it.

---

## 1. "Post-quantum" is a symmetric-only claim today

The only post-quantum property is **symmetric-by-key-size**. AES-256-GCM and Argon2id retain useful
margin against a quantum adversary because Grover's algorithm only *halves* their effective strength
(AES-256 ≈ 128-bit post-quantum). **No post-quantum asymmetric KEM is shipped** — there is no ML-KEM, no
X-Wing, no hybrid wrap. Key-encryption keys come from `PostQuantum.KeyManagement`, which is itself
honest that it ships no asymmetric PQ KEM in its current release.

**Impact:** do not describe a deployment on this release as “quantum-safe key exchange.” The forward
property you get is that the *symmetric* layer doesn't need re-encryption when large quantum computers
arrive.

**Closing it:** roadmap item — hybrid ML-KEM KEK wrapping, tracking `PostQuantum.KeyManagement`.

## 2. Recovered plaintext is an immutable `string`

`Unprotect` returns `string`. .NET strings are immutable and interned-eligible, so a decrypted secret
**cannot be reliably zeroed** and may linger on the managed heap until garbage collection (and possibly
in a swap file or crash dump).

We do zero the intermediate byte buffers used during encrypt and decrypt, and `ContentKey` from
`PostQuantum.KeyManagement` zeroes its key material on dispose. But the final plaintext, once it is a
`string`, is out of our hands.

**Impact:** this library is not suitable on its own for the strictest in-memory-secret threat models
(e.g. defending against another process reading your heap).

**Closing it:** roadmap item — an `ISecret` / `IMemoryOwner<byte>`-returning API that never produces a
`string`.

## 3. No built-in CLI to mint or rotate tokens

Today you protect values from code (or the sample's `/secrets/protect` endpoint). There is no
`dotnet`-tool you can run in CI or an ops shell to seal a value, so the “mint a token, paste it into
appsettings” workflow requires a small program.

**Closing it:** roadmap item — a `dotnet pqc-config` global tool with `protect` / `unprotect` /
`rotate` verbs.

## 4. No bulk re-seal / migration helper

After a key rotation, old tokens still open (previous KEKs are retained), but they remain *wrapped under
the old KEK*. There is no one-call helper to walk a configuration source and re-seal every protected
value under the new active KEK. You can do it manually (`Unprotect` then `Protect`, or
`IContentKeyProvider.RewrapAsync` for the wrapped-key-only path).

**Closing it:** roadmap item — a `ReprotectAsync(IConfiguration, …)` / keyring-aware bulk rewrap.

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

No third party has reviewed this code or its envelope construction. The cryptographic primitives are the
.NET BCL's and `PostQuantum.KeyManagement`'s — not re-implemented here — which limits the blast radius,
but the framing, token format, and integration logic are unreviewed.

**Closing it:** roadmap item — external review before a stable `1.0`.

## 7. Supply-chain provenance is partial

Deterministic builds, SourceLink, symbol packages, and a CycloneDX SBOM are in place. **Author
code-signing certificate and build/SLSA attestations are not yet** — see
[`docs/supply-chain.md`](docs/supply-chain.md) for exactly what is and isn't present.

## 8. Preview stability

The public API and the `pqc.v1` token format are **not frozen**. A future preview may change either.
When the token format changes, the prefix version (`pqc.v1.`) will change with it so old and new tokens
are distinguishable, but cross-version readers are not guaranteed before `1.0`.

---

*If a gap here is a blocker for you, please open an issue — it helps prioritise the roadmap.*
