#!/usr/bin/env bash
# Build the patchmgr/windows-vuln:ltsc2022 image.
#
# Requires Docker Desktop in Windows-containers mode on a Windows
# host. The base image (~2-3 GB) is pulled on first run.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[build] docker build -> patchmgr/windows-vuln:ltsc2022"
docker build -t patchmgr/windows-vuln:ltsc2022 -f Dockerfile .
echo "[build] done. Run scripts/run.sh next."
