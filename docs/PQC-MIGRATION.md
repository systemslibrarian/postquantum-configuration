# Adopting a post-quantum posture for configuration secrets

A practical, honest guide: why you might act now, exactly what protection each choice buys you, and a
step-by-step migration using the library and the `pqc-config` CLI. If you want the one-file quickstart
instead, see [`GETTING-STARTED.md`](GETTING-STARTED.md).

## Why act before a quantum computer exists

The attack that matters for *stored secrets* is **harvest now, decrypt later**: an adversary who copies
your repository, backups, or config server today can simply keep the ciphertext and wait for the
cryptography to fall. You don't get to re-encrypt data an attacker already exfiltrated.

That threat has a shape, and it dictates the priority order:

- **Asymmetric crypto breaks first.** Shor's algorithm breaks RSA and elliptic-curve key exchange
  outright on a large fault-tolerant quantum computer.
- **Symmetric crypto mostly survives.** Grover's algorithm only *halves* effective key strength —
  AES-256 degrades to ~128-bit security, which remains comfortably out of reach.

Configuration secrets are long-lived (connection strings and API keys routinely outlive the machines
they were minted on), widely copied (repos, backups, CI caches, laptops), and boring to rotate — the
exact profile harvest-now-decrypt-later punishes.

## What each provider actually gives you

Be precise about the claim you deploy — the two providers differ, and we would rather you under-claim.

| | Default provider (Argon2id keyring) | Hybrid provider (`HybridKemContentKeyProvider`) |
|---|---|---|
| Value encryption | AES-256-GCM | AES-256-GCM |
| Content-key wrapping | Symmetric KEK derived via Argon2id | **ML-KEM-768** (FIPS 203) **+** ECDH P-256 → HKDF-SHA256 |
| Post-quantum property | **Symmetric-by-key-size** — ~128-bit vs. Grover; no asymmetric KEM anywhere to break | Post-quantum **asymmetric** key wrapping — secure unless *both* ML-KEM-768 and P-256 fall |
| Wrong way to describe it | "quantum-safe key exchange" (there is no key exchange) | "standardised PQC" (the combiner is the standard concatenate-into-HKDF pattern, but not a named standard, and unaudited — [KNOWN-GAPS §1](../KNOWN-GAPS.md)) |
| Requirements | .NET 8+ anywhere | .NET 10+ with ML-KEM (Linux: OpenSSL 3.5+) |
| Fits when | One trust domain holds the passphrase and both seals and opens | Sealing and opening are separated: anyone with the public key seals, only the private-key holder opens |

**Practical guidance:** the default provider is the right start for most apps — there is no asymmetric
primitive in the path for a quantum computer to attack, which is itself a strong PQ posture for data at
rest. Reach for the hybrid provider when you need public-key workflows (CI seals secrets it must never
be able to read back) *and* you control the runtime (.NET 10+).

## Migrating an existing app

Protected and plaintext values coexist, so the rollout is incremental and reversible throughout.

### 1. Install

```bash
dotnet add package PostQuantum.Configuration
dotnet tool install --global PostQuantum.Configuration.Tool
```

### 2. Create a keyring and bulk-protect your config file

```bash
export PQC_PASSPHRASE='a strong passphrase'   # from your secret store — never a checked-in file

# See what would change first (needs no keys at all):
pqc-config protect-file --file appsettings.json --section ConnectionStrings --dry-run

# Seal it (creates keyring.txt on first use; atomic — the file is replaced only if every value seals):
pqc-config protect-file --keyring keyring.txt --file appsettings.json --section ConnectionStrings
```

Select what to seal with `--keys ConnectionStrings:Default,ApiKeys:0` (exact keys — a typo is an
error, not a silent skip), `--section <name>`, or `--all`. Re-running is harmless: existing tokens are
skipped. Add `--bind-key` if you want each token cryptographically bound to its configuration key
(swap resistance — pair it with `bindKeyAsContext: true` below).

### 3. Wrap your configuration sources

```csharp
builder.Services.AddPostQuantumKeyManagement(o =>
{
    o.Passphrase = builder.Configuration["KeyManagement:Passphrase"]!; // env var / secret store
    o.KeyringPath = "keyring.txt";
});
builder.Services.AddPostQuantumConfiguration();

builder.Configuration.Sources.Clear();
builder.Configuration
    .AddEncrypted(
        new JsonConfigurationSource { Path = "appsettings.json", Optional = false, ReloadOnChange = true },
        () => builder.Services.BuildServiceProvider().GetRequiredService<IConfigurationProtector>())
    .AddEnvironmentVariables();
```

Application code is unchanged — `GetConnectionString("Default")` now returns the decrypted value.

### 4. Rotate the credentials you just encrypted

Encryption protects the *new* value. Any plaintext that ever shipped in a repo or backup is still
compromised — rotate it at its source (the database, the API provider), then seal the replacement.

## The rotation runbook

Rotate the key-encryption key periodically and after any suspected exposure:

```bash
pqc-config rotate --keyring keyring.txt                            # new active KEK; old tokens still open
pqc-config reprotect-file --keyring keyring.txt --file appsettings.json   # migrate every token, all-or-nothing
```

`inspect` shows which KEK wraps a token — no keys needed — so you can verify the migration:

```bash
pqc-config inspect --token pqc.v1.AQ...
# format version:  1
# provider:        local.v1
# key id:          <the active key id after reprotect-file>
# ...
```

In code, the same loop is `ProtectedTokenInfo.TryInspect` to find stale tokens and
`Reprotect` / `ReprotectAllAsync` to migrate them.

## Adopting hybrid post-quantum key wrapping (.NET 10+)

When you want public-key workflows — CI seals secrets it must never be able to read back, or you want
the content-key wrapping itself to rest on a post-quantum KEM — move to the hybrid provider. The whole
lifecycle works from the shell:

```bash
# One-time: generate a recipient key pair. The private key goes straight into a secret manager.
pqc-config keygen --public recipient.pub --private recipient.key
# -> hk-… (the recipient fingerprint; `inspect` shows the same id on every token sealed to it)

# Migrate an existing keyring-sealed file onto hybrid ML-KEM wrapping — one atomic command:
pqc-config reprotect-file --keyring keyring.txt --to-recipient recipient.pub --file appsettings.json

# From now on, anyone (CI included) can seal with the PUBLIC key…
pqc-config protect-file --recipient recipient.pub --file appsettings.json --all

# …and only the private-key holder can open:
pqc-config unprotect --recipient recipient.key --token pqc.v1.…
```

Key files are self-describing (`pqc.hybrid.pub.v1.…` / `pqc.hybrid.key.v1.…`), so handing the wrong
file to a command is a clear error — and asking a public key to decrypt fails up front, not at unwrap
time. In code, the same roles are `HybridKemContentKeyProvider.ImportPublicKey` (seal-only) and
`ImportPrivateKey` (seal + open).

## FAQ

**Is my configuration "quantum-safe" after this?**
Say it precisely: with the default provider, your secrets at rest are protected by symmetric
cryptography that retains ~128-bit strength against a quantum adversary, and there is no asymmetric
primitive in the path to break. With the hybrid provider, the key wrapping additionally survives unless
both ML-KEM-768 and ECDH P-256 fall. Neither claim covers your TLS transport, your vault, or secrets in
process memory — see [`threat-model.md`](threat-model.md).

**Do I need the hybrid provider to be "post-quantum"?**
No. The harvest-now-decrypt-later threat to *stored config* is answered by the default provider's
symmetric envelope. The hybrid provider buys you public-key workflows with a PQ KEM — adopt it for that
capability, not for the label.

**Why not just a vault?**
Use one if you can — access policies and audit logs are properties this library deliberately does not
have. This library covers what still lands on disk: the values in `appsettings.json`, backups, and
repos, and defence in depth in front of the vault. See the comparison in the
[README](../README.md#when-to-use-this-and-when-not-to).

**What happens when a hybrid-KEM standard (e.g. X-Wing) lands in .NET?**
The roadmap is to align the hybrid provider with the named scheme. The token envelope is versioned
(`pqc.v1.` prefix, wrapped-key blob is provider-defined), so migration is a re-seal
(`reprotect-file`), not a format break.

**Has any of this been audited?**
No — and an external audit is **not currently scheduled**. The primitives are the .NET BCL's and
`PostQuantum.KeyManagement`'s; the envelope and combiner here are unreviewed. [KNOWN-GAPS
§6](../KNOWN-GAPS.md) is the standing, honest statement — please reach out if you can review or
sponsor a review.

---

*To God be the glory — 1 Corinthians 10:31.*
