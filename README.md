# PostQuantum.Configuration

**Secure-by-default encryption for sensitive configuration — connection strings, API keys, and whole
appsettings sections — for .NET 8, 9, and 10.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Target](https://img.shields.io/badge/.NET-8.0%20%7C%209.0%20%7C%2010.0-512BD4)](https://dotnet.microsoft.com/)

> **Status: `1.3.0` — stable.** The public API and the `pqc.v1` token format are **frozen** and follow
> SemVer; every token minted by a `0.x` preview still decrypts. **Not independently audited** — an
> external audit is not currently scheduled, and `1.0` is a stability commitment, not an audit claim.
> See [Security posture](#security-posture), [`SECURITY.md`](SECURITY.md), and
> [`KNOWN-GAPS.md`](KNOWN-GAPS.md) — we would rather under-claim than overstate.
>
> Ships with an optional [hybrid post-quantum key-wrapping provider](#optional-hybrid-post-quantum-key-wrapping-ml-kem-768--ecdh-p-256)
> (ML-KEM-768 + ECDH P-256), a [zeroable `Secret`](#avoiding-lingering-plaintext-with-secret) return
> type, [re-seal helpers](#re-sealing-after-rotation) for rotation, and the
> [`pqc-config` CLI](#cli-pqc-config).

---

## Table of contents

- [Why this library exists](#why-this-library-exists)
- [When to use this (and when not to)](#when-to-use-this-and-when-not-to)
- [Install](#install)
- [60-second tour](#60-second-tour)
- [Adopting a post-quantum posture (migration guide)](docs/PQC-MIGRATION.md)
- [Usage](#usage)
  - [Protect and read a value](#protect-and-read-a-value)
  - [Transparent decryption in `IConfiguration`](#transparent-decryption-in-iconfiguration)
  - [Dependency injection](#dependency-injection)
  - [Context binding (swap resistance)](#context-binding-swap-resistance)
  - [Key rotation](#key-rotation)
  - [Re-sealing after rotation](#re-sealing-after-rotation)
  - [Avoiding lingering plaintext with `Secret`](#avoiding-lingering-plaintext-with-secret)
  - [Optional: hybrid post-quantum key wrapping (ML-KEM-768 + ECDH P-256)](#optional-hybrid-post-quantum-key-wrapping-ml-kem-768--ecdh-p-256)
  - [CLI: `pqc-config`](#cli-pqc-config)
- [Token format](#token-format)
- [Public API at a glance](#public-api-at-a-glance)
- [Security posture](#security-posture)
- [Threat model (short form)](#threat-model-short-form)
- [Supply chain](#supply-chain)
- [Samples](#samples)
- [Compatibility](#compatibility)
- [Building from source](#building-from-source)
- [Project status & roadmap](#project-status--roadmap)
- [License](#license)

---

## Why this library exists

Secrets end up in configuration. Connection strings, third-party API keys, signing secrets, SMTP
passwords — they live in `appsettings.json`, environment variables, and config servers, and they leak
the same way every time: a repo goes public, a backup is over-shared, a log line prints a section, a
laptop is lost.

The standard .NET answer is `IDataProtection` (great, but DPAPI / ASP.NET-keyring shaped and
classical-only) or "put it in a vault" (correct, but not every value justifies a Key Vault round-trip,
and you still want defence in depth for what does land on disk). What's missing is a **small, honest,
secure-by-default primitive** to encrypt individual configuration values so the bytes at rest are
ciphertext — and to decrypt them transparently when the app reads them.

`PostQuantum.Configuration` is that primitive. It builds directly on
[`PostQuantum.KeyManagement`](https://github.com/systemslibrarian/PostQuantum.KeyManagement)'s
envelope-encryption engine, so key custody, rotation, and (later) cloud-KMS providers are a solved
problem you plug into, not something this library reinvents. Each value is sealed with its own 256-bit
content key under **AES-256-GCM**; the content key is wrapped by an Argon2id-derived (or KMS) key. The
result is a compact token you can commit to source control, and a configuration layer that hands your
code plaintext while the repo only ever holds ciphertext.

It is part of the `PostQuantum.*` family alongside
[`PostQuantum.Jwt`](https://github.com/systemslibrarian/postquantum-jwt) and
[`PostQuantum.KeyManagement`](https://github.com/systemslibrarian/PostQuantum.KeyManagement), and holds
to the same discipline: **honesty over polish, fail-closed always, no rolled-your-own crypto.**

## When to use this (and when not to)

**Reach for it when:**

- You want secrets at rest in `appsettings.json` / config servers / env vars to be **ciphertext**, not
  plaintext, with decryption that's transparent to application code.
- You want a **single, auditable primitive** for "encrypt this config value" across services, with key
  rotation handled by `PostQuantum.KeyManagement`.
- You want **defence in depth** in front of, or instead of, a vault for values that don't justify a
  per-read network call — and a forward-looking posture as post-quantum migration begins.
- You want to keep an **air-gapped / local** story (Argon2id-derived keys, no external service) and
  later swap in a cloud KMS without touching application code.

**Prefer something else when:**

| Need | Better fit |
|---|---|
| Centralised secret storage, access policies, audit logs, dynamic secrets | A managed vault (Azure Key Vault, AWS Secrets Manager, HashiCorp Vault) — and use this for the values that still land on disk. |
| Protecting ASP.NET cookies, antiforgery tokens, OAuth state | `Microsoft.AspNetCore.DataProtection` — that's exactly its job. |
| Quantum-safe **key exchange / transport** for tokens on the wire | `PostQuantum.Jwt` (PQ JOSE/JWE). This library's [hybrid provider](#optional-hybrid-post-quantum-key-wrapping-ml-kem-768--ecdh-p-256) does PQ asymmetric *key wrapping* for config values, not transport. |
| Encrypting files or large blobs | A streaming AEAD / file-encryption library. |

Honest framing: the win here is **good defaults and ergonomics**, not novel cryptography. The
primitives are the ones the .NET BCL already ships.

## Install

```bash
dotnet add package PostQuantum.Configuration
```

This pulls in [`PostQuantum.KeyManagement`](https://www.nuget.org/packages/PostQuantum.KeyManagement)
(the key engine) and the `Microsoft.Extensions.Configuration` / DI abstractions.

## 60-second tour

```csharp
using Microsoft.Extensions.Configuration;
using PostQuantum.Configuration;
using PostQuantum.KeyManagement.Local;

// 1. A key provider. (In a host: AddPostQuantumKeyManagement. Passphrase from a secret store.)
using var keys = LocalContentKeyProvider.Create("a strong passphrase", LocalKekOptions.Interactive);
IConfigurationProtector protector = new PostQuantumConfigProtector(keys);

// 2. Seal a secret → a token safe to commit.
string token = protector.Protect("Host=db;Username=app;Password=s3cr3t");

// 3. Read it back transparently through configuration.
IConfiguration config = new ConfigurationBuilder()
    .AddEncrypted(
        new Microsoft.Extensions.Configuration.Memory.MemoryConfigurationSource
        {
            InitialData = new Dictionary<string, string?> { ["ConnectionStrings:Db"] = token },
        },
        protector)
    .Build();

string? plaintext = config.GetConnectionString("Db"); // "Host=db;Username=app;Password=s3cr3t"
```

## Usage

### Protect and read a value

```csharp
string token = protector.Protect("sk-live-0123456789");   // -> "pqc.v1.…"
string secret = protector.Unprotect(token);               // -> "sk-live-0123456789"

// Untrusted input? Don't let a bad token throw:
if (protector.TryUnprotect(token, out string? value))
{
    // use value
}

// Async variants exist for cloud-KMS providers where unwrap is a network call:
string t = await protector.ProtectAsync("secret");
string s = await protector.UnprotectAsync(t);
```

### Transparent decryption in `IConfiguration`

Wrap any configuration source. Protected (`pqc.v1.`) values are decrypted on read; everything else
passes through untouched:

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Configuration.Sources.Clear();
builder.Configuration
    .AddEncrypted(
        new JsonConfigurationSource { Path = "appsettings.json", Optional = false, ReloadOnChange = true },
        () => protector)              // factory: resolved lazily, on first protected read
    .AddEnvironmentVariables();
```

Now `appsettings.json` can hold `"ConnectionStrings:Default": "pqc.v1.…"` and your handlers read it as
an ordinary string. Decryption is lazy and cached; a config reload clears the cache.

### Dependency injection

```csharp
// PostQuantum.KeyManagement provides the key engine…
builder.Services.AddPostQuantumKeyManagement(o =>
{
    o.Passphrase = builder.Configuration["KeyManagement:Passphrase"]!; // from a secret store / env
    o.KeyringPath = "keyring.bin";                                     // durable, non-secret
});

// …and this library layers the protector on top.
builder.Services.AddPostQuantumConfiguration();   // registers IConfigurationProtector
```

Resolve `IConfigurationProtector` anywhere, or use it as the factory for `AddEncrypted`.

### Context binding (swap resistance)

Optionally bind a value to a logical slot so a token can't be lifted from one place and dropped into
another (e.g. swapping the primary DB password onto the replica key):

```csharp
string token = protector.Protect(secret, context: "ConnectionStrings:Primary");
protector.Unprotect(token, context: "ConnectionStrings:Primary"); // ok
protector.Unprotect(token, context: "ConnectionStrings:Replica"); // throws — context mismatch
```

The transparent layer can bind each value's configuration key as its context automatically:

```csharp
builder.Configuration.AddEncrypted(jsonSource, () => protector, bindKeyAsContext: true);
```

### Key rotation

Rotation lives in `PostQuantum.KeyManagement`. Rotate the key-encryption key; **old tokens still open**
because previous KEKs stay available for unwrapping, and new values seal under the new active KEK:

```csharp
keys.Rotate("a new passphrase", LocalKekOptions.Interactive);
protector.Unprotect(oldToken); // still works
```

### Re-sealing after rotation

After a rotation, old tokens still open but remain *wrapped under the old key*. Migrate them to the new
active key with the re-seal helpers (plaintext is handled through a zeroable `Secret` internally):

```csharp
// One value:
string fresh = protector.Reprotect(oldToken);

// A whole map of configuration values, in place — plaintext entries are left untouched:
int resealed = await protector.ReprotectAllAsync(values);   // values: IDictionary<string,string?>
```

### Avoiding lingering plaintext with `Secret`

`Unprotect` returns a `string`, which the CLR cannot reliably zero. For paths that can work with bytes,
recover into a `Secret` that zeroes its buffer on dispose:

```csharp
using Secret secret = protector.UnprotectToSecret(token);
Use(secret.Bytes);              // ReadOnlySpan<byte>, valid until disposed
// string s = secret.Reveal(); // only if an API forces a string on you
```

This is a mitigation, not a guarantee — see [`KNOWN-GAPS.md`](KNOWN-GAPS.md) — but it removes the
unavoidable lingering-`string` for byte-friendly code.

### Optional: hybrid post-quantum key wrapping (ML-KEM-768 + ECDH P-256)

By default, content keys are wrapped by `PostQuantum.KeyManagement` (symmetric, Argon2id-derived KEK —
post-quantum *by key size*). For true post-quantum **asymmetric** key wrapping, use the hybrid provider:
each content key is wrapped to a recipient key pair using **ML-KEM-768** (FIPS 203, the post-quantum
half) **and** **ECDH P-256** (the classical half), combined via HKDF-SHA256 + AES-256-GCM. The wrap
stays secure unless *both* are broken.

```csharp
using PostQuantum.Configuration.Hybrid;

// Recipient (the service that decrypts): generate once, persist the private key in a secret store/KMS.
using var recipient = HybridKemContentKeyProvider.Generate();
byte[] publicKey  = recipient.ExportPublicKey();   // distribute to senders; safe to share
byte[] privateKey = recipient.ExportPrivateKey();  // SENSITIVE — store in a secret manager only

// Anyone with the public key can seal (wrap-only):
using var sealer = HybridKemContentKeyProvider.ImportPublicKey(publicKey);
string token = new PostQuantumConfigProtector(sealer).Protect("Host=db;Password=quantum-safe;");

// The recipient (private key) opens it:
using var opener = HybridKemContentKeyProvider.ImportPrivateKey(privateKey);
string secret = new PostQuantumConfigProtector(opener).Unprotect(token);
```

`HybridKemContentKeyProvider` is an `IContentKeyProvider`, so it drops into everything above —
`AddEncrypted`, DI, `Reprotect`, `Secret`. The same workflow is available from the shell:
`pqc-config keygen` / `--recipient` / `reprotect-file --to-recipient` (see [CLI](#cli-pqc-config)).

> **Requirements & honesty.** Needs **.NET 10+** and a platform where ML-KEM is available (on Linux,
> **OpenSSL 3.5+**); the factory methods throw `PlatformNotSupportedException` otherwise. The combiner
> follows the standard concatenate-into-HKDF, transcript-bound pattern, but this specific construction
> is **not a named standard and has not been independently audited.** See
> [`KNOWN-GAPS.md`](KNOWN-GAPS.md) and [`docs/threat-model.md`](docs/threat-model.md).

### CLI: `pqc-config`

A companion `dotnet` tool ([`PostQuantum.Configuration.Tool`](src/PostQuantum.Configuration.Tool))
covers the whole lifecycle from a shell or CI pipeline — single values, whole config files, rotation,
and keyless token inspection:

```bash
dotnet tool install --global PostQuantum.Configuration.Tool

export PQC_PASSPHRASE='a strong passphrase'           # keep secrets out of shell history
echo 'Host=db;Password=s3cr3t' | pqc-config protect --keyring keyring.txt   # -> pqc.v1.…
pqc-config unprotect --keyring keyring.txt --token pqc.v1.…

# Bulk-seal an appsettings.json — atomic (all values seal, or the file is untouched),
# idempotent (existing tokens are skipped), previewable (--dry-run needs no keys):
pqc-config protect-file --keyring keyring.txt --file appsettings.json --section ConnectionStrings
pqc-config protect-file --file appsettings.json --all --dry-run

# Rotate, then migrate every token in the file onto the new key — all-or-nothing:
pqc-config rotate         --keyring keyring.txt
pqc-config reprotect-file --keyring keyring.txt --file appsettings.json

# Inspect a token's non-secret metadata (which key wraps it?) — no keyring needed:
pqc-config inspect --token pqc.v1.…

# Hybrid post-quantum key wrapping from the shell (.NET 10+): generate a recipient
# key pair, seal with the PUBLIC key (CI can mint tokens it can never read back),
# open with the private key — and migrate an existing keyring-sealed file onto
# hybrid ML-KEM wrapping in one atomic command:
pqc-config keygen --public recipient.pub --private recipient.key
pqc-config protect-file --recipient recipient.pub --file appsettings.json --all
pqc-config unprotect    --recipient recipient.key --token pqc.v1.…
pqc-config reprotect-file --keyring keyring.txt --to-recipient recipient.pub --file appsettings.json

# CI guardrails — fail the build on plaintext secrets (keyless heuristic scan) or on
# tokens that won't decrypt with the key source you intend to deploy:
pqc-config audit --file appsettings.json
pqc-config check --keyring keyring.txt --file appsettings.json --require ConnectionStrings:Default
```

`--bind-key` on the file commands binds each value to its configuration key (context binding, above).
The end-to-end walkthrough — including why and when — is in
[`docs/PQC-MIGRATION.md`](docs/PQC-MIGRATION.md).

## Token format

A protected value is a self-contained envelope rendered as text:

```
pqc.v1.<base64url(body)>
```

- **`pqc.v1.`** — a stable, greppable prefix. `IConfigurationProtector.IsProtected(value)` is just a
  prefix check; the transparent layer uses it to decide what to decrypt.
- **body** — a compact, big-endian, length-prefixed binary blob:
  `[version][wrapped-content-key token][12-byte nonce][AES-256-GCM ciphertext][16-byte tag]`.

The wrapped content key is `PostQuantum.KeyManagement`'s own portable `WrappedContentKey` token, so a
value carries everything needed to recover its data-encryption key from the provider — no shared
per-process state. (With the hybrid provider, that wrapped-key blob carries the ML-KEM ciphertext and
the ephemeral ECDH public key instead — the token envelope is unchanged.) The decoder uses
**overflow-safe length arithmetic** and caps every field at 1 MiB, so a hostile token cannot trigger a
giant allocation or an out-of-bounds read.

## Public API at a glance

| Member | Purpose |
|---|---|
| `IConfigurationProtector` | `Protect` / `Unprotect` / `TryUnprotect` / `UnprotectToSecret` (+ async), and `static IsProtected`. |
| `PostQuantumConfigProtector` | Default implementation over `IContentKeyProvider`. |
| `Secret` | Zeroable, byte-backed recovered secret (disposes → zeroed). |
| `ConfigurationProtectionException` | Single, opaque failure type for malformed / tampered / wrong-context tokens. |
| `builder.AddEncrypted(source, …)` | Transparent decrypt-on-read wrapper for any `IConfigurationSource`. |
| `config.GetDecrypted(key, protector)` | Explicit decrypt-on-read for one value. |
| `protector.DecryptIfProtected(value)` | Decrypt if it's a token, pass through otherwise. |
| `protector.Reprotect` / `ReprotectAllAsync` | Re-seal values under the active key after rotation. |
| `ProtectedTokenInfo.TryInspect(token, out info)` | Keyless, non-throwing token inspection: format version, provider, wrapping key id (find stale tokens after rotation). |
| `protector.VerifyAsync()` / `Verify()` | Startup self-test: round-trips a random canary so a broken key source fails the deploy at boot, not on the first request. |
| `services.AddPostQuantumConfiguration()` | DI registration over a registered `IContentKeyProvider`. |
| `HybridKemContentKeyProvider` *(net10+)* | Hybrid ML-KEM-768 + ECDH P-256 key-wrapping `IContentKeyProvider`. |
| `pqc-config` *(separate tool package)* | CLI to protect / unprotect / rotate. |

## Security posture

We aim to be honest about exactly what this library does and does not give you.

**Scope of the "post-quantum" claim.** With the **default** (symmetric) key provider, the post-quantum
property is **symmetric-by-key-size** — AES-256-GCM and Argon2id keep useful margin against a quantum
adversary because Grover's algorithm only *halves* their effective strength (AES-256 → ~128-bit), and no
asymmetric KEM is involved. With the **optional hybrid provider** (ML-KEM-768 + ECDH P-256), you also
get post-quantum **asymmetric** key wrapping — but that construction is non-standard and unaudited (see
its [usage note](#optional-hybrid-post-quantum-key-wrapping-ml-kem-768--ecdh-p-256)). Choose your wording
to match the provider you deploy, and see [`KNOWN-GAPS.md`](KNOWN-GAPS.md) for the precise scope.

**What you get**

- **Authenticated encryption.** AES-256-GCM — tampering with any byte is detected and fails closed,
  never silently decrypted to garbage. Every single-byte corruption of a token is rejected (there's a
  test that proves it).
- **Fresh key + nonce per value.** Each `Protect` mints a new 256-bit content key and a new random
  nonce, so identical plaintexts produce different tokens and there is no deterministic-equality leak.
- **Native primitives, no hand-rolled crypto.** AES-GCM is the .NET BCL; key custody, Argon2id, and
  wrapping are `PostQuantum.KeyManagement`. This library writes the envelope and the framing, not the
  cryptography.
- **Fail-closed, opaque failures.** Malformed token, tampered ciphertext, wrong key, or wrong context
  all surface as one `ConfigurationProtectionException` (or `TryUnprotect == false`) — callers can't
  distinguish failure modes, and the message never leaks which one it was.
- **Hostile-input resistance.** Token decoding uses overflow-safe length arithmetic and a 1 MiB field
  cap; `TryUnprotect` never throws on bad input.
- **Optional context binding** for swap resistance (above).

**What you must know**

- **Recovered plaintext is a `string`.** .NET strings are immutable and can't be reliably zeroed, so a
  decrypted secret may linger on the managed heap until GC. Intermediate byte buffers are zeroed. This
  is an inherent limit of any string-returning API — see [`KNOWN-GAPS.md`](KNOWN-GAPS.md).
- **Confidentiality rests entirely on the key provider.** A weak passphrase, a leaked keyring +
  passphrase, or an unprotected KMS makes the ciphertext openable. Use a strong Argon2id work factor
  and treat the passphrase as a real secret.
- **Not a vault.** No access policies, no audit log, no per-secret authorisation. Pair with one for
  those properties.
- **Not independently audited.** The API and `pqc.v1` token format are stable (SemVer, as of `1.0`),
  but no third party has reviewed the code, and an external audit is not currently scheduled — see
  [`KNOWN-GAPS.md`](KNOWN-GAPS.md) §6.

Full detail: [`SECURITY.md`](SECURITY.md), [`docs/threat-model.md`](docs/threat-model.md),
[`KNOWN-GAPS.md`](KNOWN-GAPS.md).

## Threat model (short form)

| The library defends against… | …but **not** |
|---|---|
| Plaintext secrets in a repo, backup, or config file | An attacker who holds **both** the keyring / KMS access **and** the passphrase |
| Tampering with stored ciphertext (AES-GCM authentication) | A weak passphrase / low Argon2id work factor (offline guessing) |
| A value being moved to the wrong slot (with context binding) | Secrets read from process memory after decryption (mitigated, not solved, by `Secret`) |
| Hostile / oversized tokens (overflow-safe, capped decoding) | A quantum break of the **classical** half alone — the ML-KEM half still holds (hybrid provider) |

The full attacker model and security invariants are in [`docs/threat-model.md`](docs/threat-model.md).

## Supply chain

This package is built for verifiable provenance:

- **Deterministic, reproducible builds** (`Deterministic`, `ContinuousIntegrationBuild` in CI).
- **Build-provenance attestation** — the release workflow attests every `.nupkg` with
  `actions/attest-build-provenance`; verify with `gh attestation verify`.
- **SourceLink + embedded untracked sources + a symbol package (`.snupkg`)** so stack traces resolve to
  exact source.
- **SBOM** (CycloneDX) generated for every release — regenerate and inspect locally:

  ```bash
  ./build/generate-sbom.sh           # writes sbom/PostQuantum.Configuration.cdx.json
  ```

- **Verify a downloaded package** before trusting it:

  ```bash
  # NuGet signature (repository countersignature)
  dotnet nuget verify PostQuantum.Configuration.1.0.0.nupkg

  # Pin and restore with integrity checking
  dotnet restore --locked-mode      # honours packages.lock.json hashes
  ```

What is **not** in place is stated plainly in [`docs/supply-chain.md`](docs/supply-chain.md): an author
code-signing certificate is still roadmap, and an external security audit is **not currently
scheduled** (see [`KNOWN-GAPS.md`](KNOWN-GAPS.md) §6).

## Samples

See [`samples/`](samples/):

- **[`QuickStart`](samples/QuickStart)** — a self-contained console tour (protect, transparent read,
  tamper rejection, rotation). `dotnet run --project samples/QuickStart`.
- **[`WebApi`](samples/WebApi)** — a production-shaped ASP.NET Core minimal API with encrypted tokens
  committed in `appsettings.json`, DI wiring, and a token-minting endpoint.
  `dotnet run --project samples/WebApi`.

## Compatibility

| Surface | Supported |
|---|---|
| Target frameworks | `net8.0`, `net9.0`, `net10.0` |
| OS | Windows, Linux, macOS — anywhere .NET 8+ runs. AES-GCM is hardware-accelerated on modern CPUs. |
| AOT / trimming | `IsAotCompatible=true`. The public surface is `string` in, `string` out. |
| Hybrid provider | **.NET 10+** and a host with ML-KEM (on Linux, **OpenSSL 3.5+**). Everything else has no such requirement. |
| Dependencies | `PostQuantum.KeyManagement`, `Microsoft.Extensions.Configuration.Abstractions` / `.Primitives` / `.DependencyInjection.Abstractions`. |

> The core library needs **no** native post-quantum primitives, so it runs identically everywhere. Only
> the optional hybrid provider requires .NET 10 + ML-KEM; it degrades to a clear
> `PlatformNotSupportedException` where unavailable.

## Building from source

```bash
dotnet build       # builds net8.0, net9.0, net10.0 — zero warnings (warnings are errors)
dotnet test        # 116 tests; hybrid ML-KEM tests run where ML-KEM is available, skip cleanly otherwise
dotnet format --verify-no-changes
dotnet pack -c Release
```

The hybrid ML-KEM tests skip themselves (with a clear reason) on hosts without ML-KEM. To run them, use
.NET 10 with OpenSSL 3.5+ — for example, point the runtime at a newer OpenSSL:

```bash
LD_LIBRARY_PATH=/path/to/openssl-3.5/lib dotnet test   # 116 tests, zero skips
```

## Project status & roadmap

`1.3.0` — **stable**. Core protect / unprotect, the transparent `IConfiguration` layer, DI, context
binding, key rotation with `Reprotect` / `ReprotectAllAsync`, the zeroable `Secret` return, keyless
token inspection (`ProtectedTokenInfo`), the hybrid **ML-KEM-768 + ECDH P-256** provider, and the
`pqc-config` CLI — including whole-file `protect-file` / `reprotect-file` — all ship and are tested
(116 tests, zero skips where ML-KEM is available). The public API and the `pqc.v1` token format are
**frozen** under SemVer, and the whole `PostQuantum.*` dependency chain is on stable releases.

**Beyond `1.0`** (see [`KNOWN-GAPS.md`](KNOWN-GAPS.md) for the honest gap list):

1. **External security review** of the envelope and the hybrid combiner. **Not currently scheduled** —
   `1.0` marks stability, not an audit; the "unaudited" caveat stays until a real review happens. If you
   can review or sponsor a review, please reach out.
2. **Author code-signing certificate** to complement the build-provenance attestations already produced.
3. **Standardised hybrid** — track the IETF/NIST hybrid-KEM work and align the construction with a named
   scheme (e.g. X-Wing) once one stabilises in the BCL.

## License

[MIT](LICENSE) © 2026 Paul Clark.

---

*To God be the glory — 1 Corinthians 10:31.*
