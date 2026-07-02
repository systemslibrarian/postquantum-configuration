# Release process

What a release of `PostQuantum.Configuration` (and `PostQuantum.Configuration.Tool`) involves, what is
automated, and — honestly — what is still manual or missing.

## Steps

1. **Bump versions.** Update `<Version>` in `src/PostQuantum.Configuration/PostQuantum.Configuration.csproj`
   and `src/PostQuantum.Configuration.Tool/PostQuantum.Configuration.Tool.csproj`, and add a
   `CHANGELOG.md` entry.
2. **Green local build.** `dotnet build -c Release` (zero warnings), `dotnet test` (zero failures), and
   `dotnet format --verify-no-changes`. Run the ML-KEM tests on a host with ML-KEM available (.NET 10 +
   OpenSSL 3.5) so the hybrid path is exercised, not just skipped.
3. **Tag.** `git tag v1.0.0 && git push origin v1.0.0`.
4. **CI release workflow** (`.github/workflows/release.yml`) runs on the tag: restore → format check →
   build → test → pack (library + tool) → SBOM → **build-provenance attestation** → upload artifacts →
   **publish to NuGet.org via Trusted Publishing**. The workflow exchanges its OIDC identity for a
   short-lived API key under the trust policy configured on NuGet.org — no long-lived API key exists
   anywhere.
5. **Verify.** After the run: `gh attestation verify` on the `.nupkg` (below), and confirm the package
   page on NuGet.org.

## What each release carries

| Signal | Automated? | Notes |
|---|---|---|
| Deterministic build | ✅ | `Deterministic`, `ContinuousIntegrationBuild` in CI |
| SourceLink + symbols | ✅ | `.snupkg` published |
| SBOM (CycloneDX) | ✅ | `build/generate-sbom.sh`, committed under `sbom/` |
| Build-provenance attestation | ✅ | `actions/attest-build-provenance` over the `.nupkg`s |
| NuGet publish (Trusted Publishing, OIDC) | ✅ | `NuGet/login` in `release.yml`; no stored API key |
| NuGet repository signature | ✅ (on publish) | Added by NuGet.org |
| Author code-signing | ❌ | No certificate yet — see [`supply-chain.md`](supply-chain.md) |
| External security audit | ❌ | Not currently scheduled — see [`KNOWN-GAPS.md` §6](../KNOWN-GAPS.md) |

## Verifying an attestation

```bash
gh attestation verify PostQuantum.Configuration.<version>.nupkg \
  --repo systemslibrarian/postquantum-configuration
```

This confirms the package was built by this repository's release workflow from the tagged commit.
