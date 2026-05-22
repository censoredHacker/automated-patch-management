#!/usr/bin/env bash
# Start (or restart) the patchmgr-windows-vuln container.
# Publishes WinRM/HTTPS on 127.0.0.1:5986 only — never on a public
# interface. The container's WinRM listener uses a self-signed cert
# generated at build time, which is why settings.yaml flips
# `winrm_server_cert_validation: ignore`.
set -euo pipefail
cd "$(dirname "$0")/.."

NAME="patchmgr-windows-vuln"
PORT="${PORT:-5986}"

if docker ps -a --format '{{.Names}}' | grep -qx "$NAME"; then
    echo "[run] removing existing container $NAME"
    docker rm -f "$NAME" >/dev/null
fi

echo "[run] starting $NAME on 127.0.0.1:$PORT"
docker run -d \
    --name "$NAME" \
    --hostname "$NAME" \
    -p "127.0.0.1:${PORT}:5986" \
    patchmgr/windows-vuln:ltsc2022 >/dev/null

# Wait for the WinRM service inside the container to come up. We poll
# for the listener via the same `winrm enumerate` we used at build
# time. First boot of a Windows container takes ~10-30s.
echo "[run] waiting for WinRM service ..."
for i in {1..60}; do
    if docker exec "$NAME" cmd /c "winrm enumerate winrm/config/Listener" >/dev/null 2>&1; then
        echo "[run] WinRM listener is up"
        break
    fi
    sleep 2
done

echo "[run] connect with: patchmgr scan --os windows \\"
echo "         --target 127.0.0.1:${PORT}:patchadmin:patchadmin \\"
echo "         --settings ./settings.yaml --report-dir ./reports"
echo "[run] stop with:    scripts/stop.sh"
