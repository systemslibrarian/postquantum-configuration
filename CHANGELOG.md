# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/). While in `0.x` preview, **minor versions may break** the
API or the `pqc.v1` token format; the prefix version will change if the wire format changes.

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

[0.1.0-preview.1]: https://github.com/systemslibrarian/postquantum-configuration/releases/tag/v0.1.0-preview.1
