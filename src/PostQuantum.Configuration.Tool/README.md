# pqc-config

Command-line companion to [**PostQuantum.Configuration**](https://www.nuget.org/packages/PostQuantum.Configuration) —
seal, open, and rotate encrypted configuration values from a shell or CI pipeline.

## Install

```bash
dotnet tool install --global PostQuantum.Configuration.Tool --prerelease
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

Run `pqc-config --help` for the full option list.

## Notes

- The **keyring file is non-secret** (salts + Argon2id parameters, no key material) and should be
  durable. The **passphrase is the secret** — never commit it; prefer `PQC_PASSPHRASE`.
- Values and tokens can be passed with `--value` / `--token` or piped on stdin. Stdin is preferred for
  secrets so they don't land in your shell history or the process list.
- Requires the .NET runtime (8, 9, or 10).

---

*To God be the glory — 1 Corinthians 10:31.*
