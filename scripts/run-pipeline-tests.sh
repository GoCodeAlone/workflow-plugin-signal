#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLUGIN_NAME="workflow-plugin-signal"
PLUGIN_DIR="$ROOT/.wfctl/test-plugins"
WFCTL="${WFCTL:-}"
WORKFLOW_REPO="${WORKFLOW_REPO:-}"

find_workflow_repo() {
  if [[ -n "$WORKFLOW_REPO" ]]; then
    [[ -d "$WORKFLOW_REPO" ]] && printf '%s\n' "$WORKFLOW_REPO" && return 0
    return 1
  fi
  local candidate
  for candidate in "$ROOT/../workflow" "$ROOT/../../../workflow"; do
    if [[ -d "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

if [[ -z "$WFCTL" ]]; then
  if WORKFLOW_REPO="$(find_workflow_repo)"; then
    mkdir -p "$ROOT/.wfctl/bin"
    (cd "$WORKFLOW_REPO" && GOWORK=off go build -o "$ROOT/.wfctl/bin/wfctl" ./cmd/wfctl)
    WFCTL="$ROOT/.wfctl/bin/wfctl"
  elif command -v wfctl >/dev/null 2>&1; then
    WFCTL="$(command -v wfctl)"
  else
    echo "wfctl not found; set WFCTL, set WORKFLOW_REPO, or install wfctl in PATH" >&2
    exit 1
  fi
fi

rm -rf "$PLUGIN_DIR/$PLUGIN_NAME"
mkdir -p "$PLUGIN_DIR/$PLUGIN_NAME"

(cd "$ROOT" && GOWORK=off go build \
  -ldflags "-X github.com/GoCodeAlone/workflow-plugin-signal/internal.Version=${VERSION:-0.0.0}" \
  -o "$PLUGIN_DIR/$PLUGIN_NAME/$PLUGIN_NAME" ./cmd/workflow-plugin-signal)
cp "$ROOT/plugin.json" "$PLUGIN_DIR/$PLUGIN_NAME/plugin.json"

"$WFCTL" test "$ROOT/tests/pipeline"
