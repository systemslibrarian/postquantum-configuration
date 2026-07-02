# pqc-config

Command-line companion to [**PostQuantum.Configuration**](https://www.nuget.org/packages/PostQuantum.Configuration) —
seal, open, and rotate encrypted configuration values from a shell or CI pipeline.

## Install

```bash
dotnet tool install --global PostQuantum.Configuration.Tool
```

## Use

```bash
# The passphrase is the real secret — keep it out of shell history with an env var.
export PQC_PASSPHRASE='a strong passphrase'

# Seal a value (creates the keyring on first use). Pipe the secret on stdin.
echo 'Host=db;Username=app;Password=s3cr3t' | pqc-config protect --keyring keyring.txt
# -> pqc.v1.AQ...

# Paste that token into appsettings.json, then recover it anywhere with the same keyring + passphrase:
pqc-config unprotect --keyring keyring.txt --token pqc.v1.AQ...
# -> Host=db;Username=app;Password=s3cr3t

# Rotate to a fresh key (same passphrase, new salt; old tokens still open):
pqc-config rotate --keyring keyring.txt
```

### Whole config files

```bash
# Preview what would be sealed (no keys needed), then seal a section in place:
pqc-config protect-file --file appsettings.json --section ConnectionStrings --dry-run
pqc-config protect-file --keyring keyring.txt --file appsettings.json --section ConnectionStrings

# Select exact keys (a missing or non-string key is an error, never a silent skip),
# or everything, and optionally bind each value to its configuration key:
pqc-config protect-file --keyring keyring.txt --file appsettings.json --keys ConnectionStrings:Default,ApiKeys:0
pqc-config protect-file --keyring keyring.txt --file appsettings.json --all --bind-key

# After a rotate, migrate every token in the file onto the new active key:
pqc-config reprotect-file --keyring keyring.txt --file appsettings.json

# Which key wraps this token? Inspect without any keys:
pqc-config inspect --token pqc.v1.AQ...
```

Both file commands are **fail-closed and atomic**: the whole file is transformed in memory and
atomically replaces the original only if every value succeeds — any failure leaves the file exactly as
it was. `protect-file` is idempotent (existing tokens are skipped on re-run). Files are parsed as
strict JSON: comments and trailing commas are rejected up front, because a rewrite would silently
destroy them.

### Hybrid post-quantum key wrapping (.NET 10+)

```bash
# Generate a recipient key pair (never overwrites existing files). The private key is the
# sensitive one — store it in a secret manager, never in source control.
pqc-config keygen --public recipient.pub --private recipient.key

# The PUBLIC key seals (CI can mint tokens it can never read back)…
pqc-config protect-file --recipient recipient.pub --file appsettings.json --all
echo 'api-key' | pqc-config protect --recipient recipient.pub

# …the PRIVATE key opens:
pqc-config unprotect --recipient recipient.key --token pqc.v1.AQ...

# Migrate an existing keyring-sealed file onto hybrid ML-KEM wrapping, atomically:
pqc-config reprotect-file --keyring keyring.txt --to-recipient recipient.pub --file appsettings.json
```

Key files are self-describing (`pqc.hybrid.pub.v1.…` / `pqc.hybrid.key.v1.…`): passing the wrong file
— or a public key where decryption is needed — is a clear, immediate error. Hybrid commands need the
.NET 10 runtime; elsewhere they fail with an actionable message rather than a missing-command surprise.

### CI guardrails

```bash
# Keyless heuristic scan: exit 1 if any plaintext value looks like a secret.
pqc-config audit --file appsettings.json

# Pre-deploy gate: every token must decrypt with the key source you intend to deploy,
# and --require keys must exist AND be protected. Plaintext is never printed. Exit 1 on failure.
pqc-config check --keyring keyring.txt --file appsettings.json --require ConnectionStrings:Default
```

Wire both into CI (see [`docs/PQC-MIGRATION.md`](../../docs/PQC-MIGRATION.md) for a GitHub Actions
snippet) so a forgotten secret, a wrong keyring, or a missed re-seal fails the build — not the deploy.

Run `pqc-config --help` for the full option list, and see
[`docs/PQC-MIGRATION.md`](../../docs/PQC-MIGRATION.md) for the end-to-end adoption walkthrough.

## Notes

- The **keyring file is non-secret** (salts + Argon2id parameters, no key material) and should be
  durable. The **passphrase is the secret** — never commit it; prefer `PQC_PASSPHRASE`.
- Values and tokens can be passed with `--value` / `--token` or piped on stdin. Stdin is preferred for
  secrets so they don't land in your shell history or the process list.
- Requires the .NET runtime (8, 9, or 10).

---

*To God be the glory — 1 Corinthians 10:31.*
