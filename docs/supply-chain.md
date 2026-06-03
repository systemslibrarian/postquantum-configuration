# Supply-chain provenance

Honest accounting of what provenance signals this package carries — and what it does **not** yet.

## What's in place

| Signal | Status | How |
|---|---|---|
| **Deterministic builds** | ✅ | `Deterministic=true`; `ContinuousIntegrationBuild=true` in CI (`Directory.Build.props`). |
| **Reproducible, source-linked** | ✅ | `Microsoft.SourceLink.GitHub`, `PublishRepositoryUrl`, `EmbedUntrackedSources`. |
| **Symbol package** | ✅ | `.snupkg` (`SymbolPackageFormat=snupkg`, `IncludeSymbols=true`) so stack traces resolve to source. |
| **Central, pinned dependencies** | ✅ | Central Package Management (`Directory.Packages.props`) — one version per dependency, transitive pinning on. |
| **Lock file restore** | ✅ (opt-in) | `dotnet restore --locked-mode` honours `packages.lock.json` hashes. Generate with `dotnet restore --use-lock-file`. |
| **SBOM (CycloneDX)** | ✅ | `./build/generate-sbom.sh` → `sbom/PostQuantum.Configuration.cdx.json`. |
| **README + license in package** | ✅ | `PackageReadmeFile`, `PackageLicenseExpression=MIT`. |
| **MIT license, explicit copyright** | ✅ | `LICENSE`, `Copyright` property. |

## What's NOT in place yet

We will not imply provenance we don't have.

| Signal | Status | Plan |
|---|---|---|
| **Author code-signing certificate** | ❌ | The `.nupkg` carries NuGet.org's repository signature once published, but not an author signature. A code-signing cert is roadmap before `1.0`. |
| **Build provenance attestation (SLSA / GitHub artifact attestations)** | ❌ | Roadmap. Intend to publish `actions/attest-build-provenance` attestations from the release workflow. |
| **Reproducible-build verification by a third party** | ❌ | Builds are deterministic; no independent rebuild-and-compare is published yet. |
| **External security audit** | ❌ | Roadmap before stable `1.0` (see [`KNOWN-GAPS.md` §6](../KNOWN-GAPS.md)). |

## Verifying a release

```bash
# 1. Verify the NuGet package signature (repository countersignature once on NuGet.org).
dotnet nuget verify PostQuantum.Configuration.<version>.nupkg

# 2. Restore with integrity checking against the committed lock file.
dotnet restore --locked-mode

# 3. Inspect the SBOM for the exact dependency graph and versions.
cat sbom/PostQuantum.Configuration.cdx.json | jq '.components[] | {name, version}'

# 4. Reproduce the build deterministically and diff the assembly (advanced).
dotnet pack -c Release /p:ContinuousIntegrationBuild=true
```

## Generating the SBOM

```bash
./build/generate-sbom.sh
```

The script uses the CycloneDX .NET tool to emit a CycloneDX 1.x JSON document covering the runtime
dependency graph of `src/PostQuantum.Configuration`. Commit the result under `sbom/` so each release's
bill of materials is auditable from the repository.
