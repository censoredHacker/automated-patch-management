#!/usr/bin/env bash
# Build the patchmgr/ubuntu-vuln:focal image.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[build] docker build -> patchmgr/ubuntu-vuln:focal"
docker build -t patchmgr/ubuntu-vuln:focal -f Dockerfile .
echo "[build] done. Run scripts/run.sh next."
