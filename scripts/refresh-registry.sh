#!/usr/bin/env bash
# Refresh the pinned copy of the Agent Action Capsule registries
# (tests/fixtures/REGISTRY.md) from a commit of agent-action-capsule, and record
# its source. Then update src/registries.ts and src/contracts.ts until
# `npm test` passes: the parity test compares them with the pinned copy.
#
#   scripts/refresh-registry.sh <commit>
set -euo pipefail
commit=${1:?usage: scripts/refresh-registry.sh <agent-action-capsule commit>}
here=$(cd "$(dirname "$0")/.." && pwd)
url="https://raw.githubusercontent.com/action-state-group/agent-action-capsule/$commit/spec/REGISTRY.md"
curl -fsSL "$url" -o "$here/tests/fixtures/REGISTRY.md"
sha=$( (command -v sha256sum >/dev/null && sha256sum || shasum -a 256) < "$here/tests/fixtures/REGISTRY.md" | cut -c1-64)
cat > "$here/tests/fixtures/REGISTRY.source.json" <<JSON
{
  "repository": "https://github.com/action-state-group/agent-action-capsule",
  "commit": "$commit",
  "path": "spec/REGISTRY.md",
  "sha256": "$sha"
}
JSON
echo "pinned REGISTRY.md at $commit (sha256 $sha); now run: npm test"
