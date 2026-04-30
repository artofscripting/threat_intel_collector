#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Threat Intel Collector — Redeploy ==="

if [[ ! -f "$SCRIPT_DIR/.env" ]]; then
    echo "No .env found in $SCRIPT_DIR — run install_ubuntu.sh first." >&2
    exit 1
fi

echo "[*] Pulling latest code from GitHub..."
git -C "$SCRIPT_DIR" pull origin main

echo "[*] Rebuilding and restarting container (keeping existing .env)..."
docker compose -f "$SCRIPT_DIR/docker-compose.yml" up --build -d

echo "[*] Logs:"
docker logs threat-intel-listener
