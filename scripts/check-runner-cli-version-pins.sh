#!/usr/bin/env bash
# Ensures Renovate or a manual edit cannot leave architecture-specific runner
# assets on different releases. Claude Code also has matching pins in the main
# image and threat-model documentation. Keep this compatible with macOS bash
# 3.2 and BSD userland so it also runs locally.

set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)

runner_amd64=$(sed -E -n \
  's/^ARG CLAUDE_AMD64_LOCK=v([0-9]+\.[0-9]+\.[0-9]+)@sha256:[0-9a-f]{64}$/\1/p' \
  "$root/Dockerfile.runner")
runner_arm64=$(sed -E -n \
  's/^ARG CLAUDE_ARM64_LOCK=v([0-9]+\.[0-9]+\.[0-9]+)@sha256:[0-9a-f]{64}$/\1/p' \
  "$root/Dockerfile.runner")
main_image=$(sed -E -n \
  's|^RUN npm install -g @anthropic-ai/claude-code@([0-9]+\.[0-9]+\.[0-9]+)$|\1|p' \
  "$root/Dockerfile")
# Backticks in this pattern are literal Markdown delimiters, not shell syntax.
# shellcheck disable=SC2016
documented=$(sed -E -n \
  's/.*`claude-code@([0-9]+\.[0-9]+\.[0-9]+)`.*/\1/p' \
  "$root/threatmodel.md")
codex_amd64=$(sed -E -n \
  's/^ARG CODEX_AMD64_LOCK=(rust-v[0-9]+\.[0-9]+\.[0-9]+)@sha256:[0-9a-f]{64}$/\1/p' \
  "$root/Dockerfile.runner")
codex_arm64=$(sed -E -n \
  's/^ARG CODEX_ARM64_LOCK=(rust-v[0-9]+\.[0-9]+\.[0-9]+)@sha256:[0-9a-f]{64}$/\1/p' \
  "$root/Dockerfile.runner")
codex_catalog=$(sed -E -n \
  's/^const CodexModelCatalogRelease = "(rust-v[0-9]+\.[0-9]+\.[0-9]+)"$/\1/p' \
  "$root/internal/worker/harness.go")
opencode_amd64=$(sed -E -n \
  's/^ARG OPENCODE_AMD64_LOCK=(v[0-9]+\.[0-9]+\.[0-9]+)@sha256:[0-9a-f]{64}$/\1/p' \
  "$root/Dockerfile.runner")
opencode_arm64=$(sed -E -n \
  's/^ARG OPENCODE_ARM64_LOCK=(v[0-9]+\.[0-9]+\.[0-9]+)@sha256:[0-9a-f]{64}$/\1/p' \
  "$root/Dockerfile.runner")
copilot_amd64=$(sed -E -n \
  's/^ARG COPILOT_AMD64_LOCK=(v[0-9]+\.[0-9]+\.[0-9]+)@sha256:[0-9a-f]{64}$/\1/p' \
  "$root/Dockerfile.runner")
copilot_arm64=$(sed -E -n \
  's/^ARG COPILOT_ARM64_LOCK=(v[0-9]+\.[0-9]+\.[0-9]+)@sha256:[0-9a-f]{64}$/\1/p' \
  "$root/Dockerfile.runner")

require_single() {
  local label=$1
  local value=$2
  local count
  count=$(printf '%s\n' "$value" | awk 'NF { count++ } END { print count + 0 }')
  if [ "$count" -ne 1 ]; then
    printf 'expected exactly one version in %s, found %s\n' "$label" "$count" >&2
    return 1
  fi
}

require_single 'Dockerfile.runner amd64 lock' "$runner_amd64"
require_single 'Dockerfile.runner arm64 lock' "$runner_arm64"
require_single 'Dockerfile npm install' "$main_image"
require_single 'threatmodel.md tool list' "$documented"
require_single 'Dockerfile.runner Codex amd64 lock' "$codex_amd64"
require_single 'Dockerfile.runner Codex arm64 lock' "$codex_arm64"
require_single 'Scrutineer Codex model catalog' "$codex_catalog"
require_single 'Dockerfile.runner OpenCode amd64 lock' "$opencode_amd64"
require_single 'Dockerfile.runner OpenCode arm64 lock' "$opencode_arm64"
require_single 'Dockerfile.runner Copilot amd64 lock' "$copilot_amd64"
require_single 'Dockerfile.runner Copilot arm64 lock' "$copilot_arm64"

if [ "$runner_amd64" != "$runner_arm64" ] || \
   [ "$runner_amd64" != "$main_image" ] || \
   [ "$runner_amd64" != "$documented" ]; then
  printf '%s\n' \
    'Claude Code version pins disagree:' \
    "  Dockerfile.runner amd64: $runner_amd64" \
    "  Dockerfile.runner arm64: $runner_arm64" \
    "  Dockerfile npm install:  $main_image" \
    "  threatmodel.md:          $documented" >&2
  exit 1
fi

printf 'Claude Code version pins agree: %s\n' "$runner_amd64"

require_pair() {
  local label=$1
  local amd64=$2
  local arm64=$3
  if [ "$amd64" != "$arm64" ]; then
    printf '%s version pins disagree:\n  amd64: %s\n  arm64: %s\n' \
      "$label" "$amd64" "$arm64" >&2
    return 1
  fi
  printf '%s version pins agree: %s\n' "$label" "$amd64"
}

require_pair 'Codex' "$codex_amd64" "$codex_arm64"
require_pair 'Codex runner and model catalog' "$codex_amd64" "$codex_catalog"
require_pair 'OpenCode' "$opencode_amd64" "$opencode_arm64"
require_pair 'Copilot' "$copilot_amd64" "$copilot_arm64"
