#!/usr/bin/env bash
# Run `patchmgr patch` against the running Windows Docker container.
#
# This script defaults to --dry-run. Pass `--no-dry-run` as the first
# argument to actually attempt KB installs inside the container.
#
# NOTE: real KB installation inside a Windows Server Core container
# is unreliable — Microsoft does not service running containers via
# Windows Update. The dry-run path exercises the full discover ->
# prioritise -> report flow, which is what this test is for.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v patchmgr >/dev/null 2>&1; then
    echo "ERROR: 'patchmgr' is not on PATH." >&2
    echo "Install it from the repo root first:" >&2
    echo "    python -m venv .venv && source .venv/Scripts/activate && pip install -e ." >&2
    echo "  (on Linux/macOS use 'source .venv/bin/activate')" >&2
    exit 127
fi

PORT="${PORT:-5986}"
USER="${USER:-patchadmin}"
PASS="${PASS:-patchadmin}"
SETTINGS="${SETTINGS:-./settings.yaml}"
SEVERITY="${SEVERITY:-high}"

DRY_FLAG="--dry-run"
if [ "${1:-}" = "--no-dry-run" ]; then
    DRY_FLAG="--no-dry-run"
    echo "[patch] !!! REAL PATCH RUN (no dry-run) !!!"
fi

echo "[patch] target=127.0.0.1:${PORT} user=${USER} severity-min=${SEVERITY} ${DRY_FLAG}"
patchmgr patch \
    --os windows \
    --target "127.0.0.1:${PORT}:${USER}:${PASS}" \
    --severity-min "${SEVERITY}" \
    --settings "${SETTINGS}" \
    --report-dir ./reports \
    --reboot manual \
    "${DRY_FLAG}"
