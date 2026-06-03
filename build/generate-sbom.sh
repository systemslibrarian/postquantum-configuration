#!/usr/bin/env bash
#
# Generate a CycloneDX SBOM for the shipped library.
# Output: sbom/PostQuantum.Configuration.cdx.json
#
# Requires the CycloneDX .NET global tool (installed on demand if missing).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="$ROOT/src/PostQuantum.Configuration/PostQuantum.Configuration.csproj"
OUT_DIR="$ROOT/sbom"
OUT_FILE="PostQuantum.Configuration.cdx.json"

echo "==> Ensuring CycloneDX tool is available"
if ! dotnet tool list --global 2>/dev/null | grep -qi 'cyclonedx'; then
  dotnet tool install --global CycloneDX
fi
export PATH="$PATH:$HOME/.dotnet/tools"

mkdir -p "$OUT_DIR"

echo "==> Generating SBOM for $PROJECT"
# -j: JSON output, -fn: fixed file name, --output: directory.
dotnet CycloneDX "$PROJECT" \
  --json \
  --output "$OUT_DIR" \
  --filename "$OUT_FILE"

echo "==> Wrote $OUT_DIR/$OUT_FILE"
