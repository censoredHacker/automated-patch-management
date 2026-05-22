#!/usr/bin/env bash
# Stop and remove the patchmgr-windows-vuln container.
set -euo pipefail
NAME="patchmgr-windows-vuln"

if docker ps -a --format '{{.Names}}' | grep -qx "$NAME"; then
    echo "[stop] removing $NAME"
    docker rm -f "$NAME" >/dev/null
    echo "[stop] done"
else
    echo "[stop] $NAME is not running"
fi
