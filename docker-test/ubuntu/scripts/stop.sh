#!/usr/bin/env bash
# Stop and remove the patchmgr-ubuntu-vuln container.
set -euo pipefail
NAME="patchmgr-ubuntu-vuln"

if docker ps -a --format '{{.Names}}' | grep -qx "$NAME"; then
    echo "[stop] removing $NAME"
    docker rm -f "$NAME" >/dev/null
    echo "[stop] done"
else
    echo "[stop] $NAME is not running"
fi
