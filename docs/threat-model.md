# Threat model

This document states the attacker model `PostQuantum.Configuration` is designed against, the security
invariants it upholds, and — explicitly — the threats it does **not** address.

## Assets

- **Configuration secrets**: connection strings, API keys, signing secrets, etc., that would otherwise
  sit in plaintext in `appsettings.json`, env vars, or a config server.
- **The key-encryption key (KEK)** and the passphrase that derives it (custody of these belongs to
  `PostQuantum.KeyManagement`).

## Attacker model

We assume an attacker who may:

1. **Read everything at rest** — the repository, `appsettings.json`, backups, build artifacts, the
   non-secret keyring blob, and any protected (`pqc.v1`) token.
2. **Tamper with stored ciphertext** — flip, truncate, append, or replace bytes of a token.
3. **Supply hostile input** — feed crafted or oversized tokens to a decoder (e.g. via a config value an
   attacker can influence).
4. **Move values around** — copy a token from one configuration key to another.

We assume the attacker does **not** have:

- both the keyring (or KMS access) **and** the passphrase,
- the ability to read the application's process memory after decryption,
- the ability to weaken the operator's chosen Argon2id work factor.

## Security invariants

The library is designed so the following hold. Each is exercised by the test suite.

| # | Invariant | Enforced by |
|---|---|---|
| I1 | **Confidentiality at rest.** Without the KEK, a token reveals nothing about the plaintext beyond its length. | AES-256-GCM under a per-value content key wrapped by the KEK |
| I2 | **Integrity / authenticity.** Any modification to a token is detected; decryption fails closed. | AES-256-GCM authentication tag |
| I3 | **No deterministic leak.** Identical plaintexts yield different tokens. | Fresh content key + fresh 96-bit nonce per `Protect` |
| I4 | **Opaque failure.** Malformed, tampered, wrong-key, and wrong-context all surface identically. | Unified `ConfigurationProtectionException` / `TryUnprotect == false` |
| I5 | **Hostile-input safety.** A crafted token cannot cause a huge allocation, an overflow, or an out-of-bounds read. | Overflow-safe length arithmetic; 1 MiB field cap; fixed nonce/tag sizes; trailing-byte check |
| I6 | **Slot integrity (opt-in).** A token sealed with a context cannot be unsealed under a different context. | Context bound into GCM additional authenticated data |
| I7 | **No silent downgrade.** Only the exact `pqc.v1` format is accepted; an unknown version is rejected, not guessed. | Version byte + prefix check in the decoder |

## Mapping invariants to attacker capabilities

- *Read at rest (1)* → defeated by **I1**, provided the KEK/passphrase are not also compromised.
- *Tamper (2)* → defeated by **I2** / **I7**.
- *Hostile input (3)* → defeated by **I5** (and **I4** keeps error behaviour uniform).
- *Move values (4)* → defeated by **I6** when context binding is enabled.

## Out of scope (non-goals)

These are real threats this library does **not** address. Pair it with the right tool.

- **KEK + passphrase compromise.** If the attacker has both, they can decrypt. That is the whole point
  of the KEK; protect it accordingly (strong passphrase, secret store, high Argon2id work factor).
- **Offline guessing of a weak passphrase.** Mitigated, not eliminated, by Argon2id. A weak passphrase
  with a low work factor is brute-forceable from a leaked keyring.
- **Secrets in process memory.** Once decrypted to a `string`, a secret can be read from the heap by
  anything with that access. See [`KNOWN-GAPS.md` §2](../KNOWN-GAPS.md).
- **Access control, audit logging, dynamic secrets.** This is not a vault. Use one for those properties.
- **Quantum break of asymmetric KEM.** None is shipped to break; the post-quantum claim is
  symmetric-only. See [`KNOWN-GAPS.md` §1](../KNOWN-GAPS.md).
- **Side channels.** Timing/cache side channels in the underlying AES-GCM / Argon2id implementations are
  out of scope and inherited from the BCL / `PostQuantum.KeyManagement`.

## Cryptographic choices

| Choice | Value | Rationale |
|---|---|---|
| Data encryption | AES-256-GCM | Authenticated, hardware-accelerated, BCL-native; 256-bit for post-quantum symmetric margin |
| Nonce | 96-bit, random per value | GCM-standard size; fresh content key per value keeps nonce-reuse risk negligible |
| Tag | 128-bit | Full GCM tag |
| Content key | 256-bit, CSPRNG, one per value | Independent envelopes; no shared per-process key state |
| KEK derivation / wrapping | Argon2id + AES-256-GCM | Delegated to `PostQuantum.KeyManagement` |
| Additional authenticated data | `"PostQuantum.Configuration/v1"` (+ optional context) | Domain separation; opt-in slot binding |
