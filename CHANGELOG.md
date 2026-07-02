# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/). As of `1.0.0` the public API and the `pqc.v1` token format
are **frozen**: breaking either requires a major version, and a wire-format change will always change
the token prefix (`pqc.vN.`) so old and new tokens are distinguishable. (During the `0.x` previews,
minor versions were allowed to break both.)

## [1.0.0] — 2026-07-02

First stable release — the version published to NuGet.org. **No `pqc.v1` token-format change** —
every token minted by any `0.x` preview still decrypts, and the format is now frozen.

### What `1.0` means (and what it does not)

- **API frozen.** The public surface of `PostQuantum.Configuration` follows SemVer from here: breaking
  changes only in a major version.
- **Token format frozen.** `pqc.v1` is stable. If the wire format ever changes, the prefix becomes
  `pqc.v2.` and a major version ships with a cross-version reader for `pqc.v1`.
- **Not an audit milestone.** An external security audit is **not currently scheduled** — `1.0` is a
  stability commitment, not a claim of independent review. The library remains
  **not independently audited**; [`KNOWN-GAPS.md`](KNOWN-GAPS.md) §6 keeps that gap on the record, and
  the internal [self-review checklist](docs/security-review-checklist.md) was run for this release.

### Added

- **Whole-file CLI workflows** — `pqc-config protect-file` bulk-seals string values in a JSON config
  file in place (`--keys` exact list where a missing or non-string key is an error, `--section`,
  `--all`; `--bind-key` context binding; `--dry-run` preview needs no keyring). Strict-JSON parse
  (comments would be destroyed by a rewrite, so they are rejected up front), in-memory transform, and
  an atomic temp-file replace: any failure leaves the file byte-for-byte untouched; re-running is
  harmless. `pqc-config reprotect-file` re-seals every token — onto the active key after a `rotate`,
  all-or-nothing.
- **Keyless token inspection** — `ProtectedTokenInfo.TryInspect(token, out info)` (library) and
  `pqc-config inspect` (CLI): format version, provider id, **wrapping key id**, wrap algorithm, and
  ciphertext length, with no key material. Non-throwing on hostile input; the key id makes tokens
  still wrapped under a retired KEK findable after a rotation. Output states plainly that well-formed
  ≠ authentic.
- **Hybrid post-quantum workflows in the CLI** (.NET 10+; a clear, actionable error on older
  runtimes) — `pqc-config keygen` generates an **ML-KEM-768 + ECDH P-256** recipient key pair as
  self-describing key files (`pqc.hybrid.pub.v1.…` / `pqc.hybrid.key.v1.…`; never overwrites key
  material); `--recipient` seals to the public key (wrap-only: CI can mint tokens it can never read
  back) and opens with the private key file, enforced up front; `reprotect-file --to-recipient`
  migrates a whole keyring-sealed file onto hybrid post-quantum wrapping in one atomic command.
- **Defensive guardrails** — `pqc-config audit`: keyless heuristic scan for plaintext values that
  look like secrets (sensitive key names, embedded `password=` credentials); exit 1 if any found —
  CI/pre-commit friendly, and honest that a heuristic cannot prove absence of secrets.
  `pqc-config check`: pre-deploy gate that test-decrypts every token with the key source you intend
  to deploy (plaintext recovered into a zeroed buffer, never printed) and `--require`s keys that must
  exist **and** be protected. `protector.VerifyAsync()` / `Verify()`: startup self-test that
  round-trips a random canary so a broken key source fails the deploy at boot, not on the first
  request (a wrap-only hybrid provider fails by design).
- **`docs/PQC-MIGRATION.md`** — an honest adoption guide: the harvest-now-decrypt-later rationale, a
  precise per-provider account of what "post-quantum" does and does not mean, the step-by-step
  migration, the rotation runbook, CI guardrails with a ready-to-paste GitHub Actions gate, and an FAQ.
- **38 more tests** (116 total, zero skips where ML-KEM is available).

### Changed

- **`PostQuantum.KeyManagement` dependency upgraded** from `0.4.0-preview.2` to the stable **`1.0.1`**
  (the whole `PostQuantum.*` suite is now on stable releases). No API or wire-format change; existing
  keyrings and tokens are unaffected.
- Docs reworked for stable status: install commands no longer need `--prerelease`; the roadmap no
  longer gates `1.0` on an external audit (see above); `SECURITY.md` support policy now covers `1.x`.
- Publishing to NuGet.org is now automated in the release workflow via **NuGet Trusted Publishing**
  (short-lived OIDC-exchanged credentials — no long-lived API key held anywhere).

### Fixed

- **The throwing `Unprotect` members now honour the opaque-failure contract for every unwrap
  failure.** A token referencing a key the provider doesn't hold, a different provider family, or a
  wrap-only (public key) provider let the key provider's own exception (`KeyNotFoundException` /
  `InvalidOperationException`) escape from `Unprotect`, `UnprotectAsync`, and `UnprotectToSecret`,
  where `ConfigurationProtectionException` is documented — and the raw message distinguished failure
  modes. All unwrap failures now collapse to the single opaque exception, matching `TryUnprotect`
  (which was already correct). Locked in by tests across provider families and for the wrap-only case.

## [0.2.0-preview.2] — 2026-06-03

Bug-fix release. No `pqc.v1` token-format change — `0.2.0-preview.1` tokens still decrypt.

### Fixed

- **Transparent config cache coherency** — `ProtectedConfigurationProvider.Set` now evicts the memoised
  plaintext for the key, so overwriting a value with a new token (or a plaintext) is reflected on the
  next read instead of returning the stale decryption.
- **`ReprotectAllAsync` is now all-or-nothing** — re-sealed tokens are staged and committed only after
  the whole batch succeeds. A malformed/failed-authentication token (or cancellation) aborts with the
  caller's map left exactly as it was found, never partially migrated. Holds the fail-closed contract.
- **`pqc-config` could silently drop a value starting with `-`** — `--value --my-secret` parsed
  `--value` as a bare flag and sealed an empty value from stdin. Added the unambiguous `--key=value`
  form (e.g. `--value=--my-secret`); usage text documents it.

### Changed

- Documented that the synchronous `PostQuantumConfigProtector` members block on the key provider and are
  intended for synchronous providers; remote/async providers should use the `…Async` members.
- `ArgMap` is now covered by tests (`InternalsVisibleTo` to the test project). **9 more tests** (78 total).

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

[1.0.0]: https://github.com/systemslibrarian/postquantum-configuration/releases/tag/v1.0.0
[0.2.0-preview.2]: https://github.com/systemslibrarian/postquantum-configuration/releases/tag/v0.2.0-preview.2
[0.2.0-preview.1]: https://github.com/systemslibrarian/postquantum-configuration/releases/tag/v0.2.0-preview.1
[0.1.0-preview.1]: https://github.com/systemslibrarian/postquantum-configuration/releases/tag/v0.1.0-preview.1
