#!/usr/bin/env bash
# Run `patchmgr scan` against the running Docker container.
#
# Assumes:
#   - the patchmgr CLI is on PATH (`pip install -e .` from repo root)
#   - the container was started via scripts/run.sh on port 2222
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v patchmgr >/dev/null 2>&1; then
    echo "ERROR: 'patchmgr' is not on PATH." >&2
    echo "Install it from the repo root first:" >&2
    echo "    python -m venv .venv && source .venv/Scripts/activate && pip install -e ." >&2
    echo "  (on Linux/macOS use 'source .venv/bin/activate')" >&2
    exit 127
fi

PORT="${PORT:-2222}"
USER="${USER:-root}"
PASS="${PASS:-root}"
SETTINGS="${SETTINGS:-./settings.yaml}"
SEVERITY="${SEVERITY:-medium}"

echo "[scan] target=127.0.0.1:${PORT} user=${USER} severity-min=${SEVERITY}"
patchmgr scan \
    --os linux \
    --target "127.0.0.1:${PORT}:${USER}:${PASS}" \
    --severity-min "${SEVERITY}" \
    --settings "${SETTINGS}" \
    --report-dir ./reports
