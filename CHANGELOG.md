# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/). While in `0.x` preview, **minor versions may break** the
API or the `pqc.v1` token format; the prefix version will change if the wire format changes.

## [0.2.0-preview.1] — 2026-06-03

Closes the entire 0.1 roadmap. Backward-compatible: `pqc.v1` tokens from 0.1 still decrypt.

### Added

- **Hybrid post-quantum key wrapping** — `HybridKemContentKeyProvider` (in `PostQuantum.Configuration.Hybrid`,
  **.NET 10+**). Wraps each content key with **ML-KEM-768** (FIPS 203) **and** **ECDH P-256**, combined
  through HKDF-SHA256 and sealed with AES-256-GCM — secure unless *both* halves break. Full transcript
  binding (label + ML-KEM ciphertext + ephemeral ECDH public in HKDF `info`). Generate / export / import
  recipient key pairs; public-only (wrap-only) and private (wrap + unwrap) modes. It's an
  `IContentKeyProvider`, so it composes with `AddEncrypted`, DI, `Reprotect`, and `Secret`.
- **Zeroable `Secret`** + `IConfigurationProtector.UnprotectToSecret` — recover plaintext into a buffer
  that is zeroed on dispose instead of an immutable, un-zeroable `string`.
- **Re-seal helpers** — `IConfigurationProtector.Reprotect(token)` and `ReprotectAllAsync(dictionary)`
  migrate values onto the active key after a rotation.
- **`pqc-config` CLI** — new `PostQuantum.Configuration.Tool` package: `protect` / `unprotect` /
  `rotate` over a persisted keyring, with stdin input so secrets stay out of shell history.
- **Build-provenance attestation** — `actions/attest-build-provenance` over the packed `.nupkg`s in a
  new `release.yml`; `docs/RELEASE.md` and `docs/security-review-checklist.md` added.
- **18 more tests** (69 total): `Secret` lifecycle, reprotect/rotation migration, and the full hybrid
  ML-KEM path (these skip with a clear reason on hosts without ML-KEM, run fully where it's available).

### Changed

- Docs reframed: the post-quantum claim now depends on the chosen provider (symmetric-by-key-size by
  default; post-quantum asymmetric with the hybrid provider). KNOWN-GAPS §1–§4, §7 updated to reflect
  closed gaps.

### Security

- The hybrid combiner uses standard primitives and the well-trodden concatenate-into-HKDF,
  transcript-bound pattern, but is **not a named standard and has not been independently audited.** The
  default provider remains symmetric-only. Still **not independently audited** overall; preview
  API/token format.

## [0.1.0-preview.1] — 2026-06-03

First public preview.

### Added

- **Core protection API** — `IConfigurationProtector` with `Protect` / `Unprotect` / `TryUnprotect`
  (sync) and `ProtectAsync` / `UnprotectAsync`, plus a static `IsProtected` prefix check.
- **`PostQuantumConfigProtector`** — the default implementation over
  `PostQuantum.KeyManagement`'s `IContentKeyProvider`. Each value is sealed with a fresh 256-bit content
  key under AES-256-GCM; the wrapped content key travels inside the token (self-contained envelope).
- **`pqc.v1` token format** — compact, versioned, URL-safe, with a greppable prefix and a
  length-prefixed body. The decoder uses overflow-safe length arithmetic and a 1 MiB field cap.
- **Transparent configuration layer** — `builder.AddEncrypted(source, …)` wraps any
  `IConfigurationSource` and decrypts protected values on read; plaintext passes through. Lazy,
  per-key cached, reload-aware.
- **Explicit helpers** — `IConfiguration.GetDecrypted(key, protector)` and
  `IConfigurationProtector.DecryptIfProtected(value)`.
- **Dependency injection** — `services.AddPostQuantumConfiguration()` registers the protector over a
  registered `IContentKeyProvider`.
- **Context binding (opt-in)** — bind a value to a logical slot via the GCM additional authenticated
  data (`context` parameter, or `bindKeyAsContext: true` on the transparent layer) for swap resistance.
- **`ConfigurationProtectionException`** — single, opaque failure type for malformed / tampered /
  wrong-key / wrong-context tokens.
- **Tests** — 51 tests, zero skips: roundtrips, single-byte-corruption rejection, cross-key isolation,
  context binding, malformed/hostile-token handling, the encoder's overflow safety, the transparent
  layer, the extensions, and DI.
- **Samples** — `QuickStart` (console, self-contained) and `WebApi` (ASP.NET Core, encrypted tokens
  committed in `appsettings.json`).
- **Docs** — README, `SECURITY.md`, `KNOWN-GAPS.md`, `docs/threat-model.md`, `docs/GETTING-STARTED.md`,
  `docs/supply-chain.md`.
- **Packaging** — multi-targets `net8.0` / `net9.0` / `net10.0`, deterministic builds, SourceLink,
  symbol package, `IsAotCompatible`, CycloneDX SBOM generation.

### Security

- The post-quantum property is **symmetric-only** (AES-256-GCM + Argon2id; ~128-bit post-quantum under
  Grover). No asymmetric ML-KEM is shipped. See [`KNOWN-GAPS.md`](KNOWN-GAPS.md).
- **Not independently audited.** Treat the API and token format as unstable until `1.0`.

[0.2.0-preview.1]: https://github.com/systemslibrarian/postquantum-configuration/releases/tag/v0.2.0-preview.1
[0.1.0-preview.1]: https://github.com/systemslibrarian/postquantum-configuration/releases/tag/v0.1.0-preview.1
