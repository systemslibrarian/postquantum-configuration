# Engineering discipline

The standards this repository holds to. They mirror the rest of the `PostQuantum.*` family.

## Principles

1. **Honesty over polish.** Claim only what is true. The post-quantum property is symmetric-only today —
   say so, everywhere it matters. Document gaps in [`KNOWN-GAPS.md`](KNOWN-GAPS.md) before they're found.
2. **Fail closed, always.** Bad token, tampered ciphertext, wrong key, wrong context → throw, or
   `TryUnprotect == false`. Never return attacker-influenced or partial plaintext. Never guess a format.
3. **No rolled-your-own crypto.** AES-GCM is the .NET BCL; key custody, Argon2id, wrapping, and rotation
   are `PostQuantum.KeyManagement`. This repo writes the envelope and the framing — not the primitives.
4. **Opaque failures.** Don't let error messages distinguish "wrong key" from "tampered" from "wrong
   context". One failure type, one message.
5. **Hostile input is the default assumption.** Every decoder uses overflow-safe length arithmetic and
   caps field sizes. A `TryDecode`/`TryUnprotect` path exists for untrusted input.

## Before opening a PR

1. `dotnet build` — green, **zero warnings** (the build treats warnings as errors).
2. `dotnet test` — green, **zero skips**.
3. `dotnet format --verify-no-changes` — clean.
4. Security-sensitive changes land **with a test** that locks in the fail-closed behaviour.
5. If you changed the token format, bump the prefix version (`pqc.vN.`) and document it in
   [`CHANGELOG.md`](CHANGELOG.md).

## Reporting vulnerabilities

Privately — see [`SECURITY.md`](SECURITY.md). Do not open a public issue.

---

*To God be the glory — 1 Corinthians 10:31.*
