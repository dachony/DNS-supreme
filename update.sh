#!/bin/bash
# DNS Supreme — Update existing installation
# Run as root: sudo bash update.sh

set -e

echo "=== DNS Supreme Update ==="
echo ""

# 1. Pull latest code
echo "[1/3] Pulling latest changes..."
git pull

# 2. Rebuild and restart
echo "[2/3] Rebuilding and restarting..."
docker compose build
docker compose up -d

# 3. Verify
echo "[3/3] Verifying..."
sleep 3
if docker ps --format '{{.Names}}' | grep -q dns-supreme; then
    HOST_IP=$(hostname -I | awk '{print $1}')
    echo ""
    echo "=== Update Complete ==="
    echo ""
    echo "Web panel:   http://${HOST_IP}:5380"
    echo "DNS server:  ${HOST_IP}:53"
    echo ""
    echo "All data, settings, and certificates are preserved."
else
    echo ""
    echo "WARNING: Container may not be running. Check with: docker compose logs"
fi
