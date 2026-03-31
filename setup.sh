#!/bin/bash
# DNS Supreme — First-time server setup
# Run as root: sudo bash setup.sh

set -e

echo "=== DNS Supreme Setup ==="
echo ""

# 1. Disable systemd-resolved (frees port 53)
if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    echo "[1/4] Disabling systemd-resolved (frees port 53)..."
    systemctl stop systemd-resolved
    systemctl disable systemd-resolved

    # Point resolv.conf to external DNS so the system can still resolve
    rm -f /etc/resolv.conf
    cat > /etc/resolv.conf <<EOF
nameserver 8.8.8.8
nameserver 1.1.1.1
EOF
    echo "      Done. System DNS set to 8.8.8.8 / 1.1.1.1"
else
    echo "[1/4] systemd-resolved already disabled, skipping."
fi

# 2. Check Docker is installed
echo "[2/4] Checking Docker..."
if ! command -v docker &>/dev/null; then
    echo "      Docker not found. Installing..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    echo "      Docker installed."
else
    echo "      Docker OK ($(docker --version | cut -d' ' -f3))"
fi

# 3. Check Docker Compose
echo "[3/4] Checking Docker Compose..."
if docker compose version &>/dev/null; then
    echo "      Docker Compose OK"
else
    echo "      ERROR: Docker Compose plugin not found."
    echo "      Install with: sudo apt install docker-compose-plugin"
    exit 1
fi

# 4. Build and start DNS Supreme
echo "[4/4] Building and starting DNS Supreme..."
docker compose build --no-cache
docker compose up -d

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Web panel:  http://$(hostname -I | awk '{print $1}'):5380"
echo "DNS server: $(hostname -I | awk '{print $1}'):53"
echo ""
echo "Default login: admin / admin"
echo "IMPORTANT: Change the default password after first login!"
echo ""
