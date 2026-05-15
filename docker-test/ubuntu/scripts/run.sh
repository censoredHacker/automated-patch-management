#!/usr/bin/env bash
# Start (or restart) the patchmgr-ubuntu-vuln container.
# Publishes ssh on 127.0.0.1:2222 only — never on a public interface.
set -euo pipefail
cd "$(dirname "$0")/.."

NAME="patchmgr-ubuntu-vuln"
PORT="${PORT:-2222}"

if docker ps -a --format '{{.Names}}' | grep -qx "$NAME"; then
    echo "[run] removing existing container $NAME"
    docker rm -f "$NAME" >/dev/null
fi

echo "[run] starting $NAME on 127.0.0.1:$PORT"
docker run -d \
    --name "$NAME" \
    --hostname ubuntu-vuln \
    -p "127.0.0.1:${PORT}:22" \
    patchmgr/ubuntu-vuln:focal >/dev/null

# Wait for sshd to come up.
for i in {1..15}; do
    if docker exec "$NAME" pgrep -x sshd >/dev/null 2>&1; then
        echo "[run] sshd is up"
        break
    fi
    sleep 1
done

echo "[run] connect with:  ssh -p ${PORT} patchadmin@127.0.0.1   (password: patchadmin)"
echo "[run] stop with:     scripts/stop.sh"
