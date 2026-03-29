# DNS Supreme v1.0.0

DNS server and network filter with web management panel. Blocks ads, malware, tracking, and threats at the DNS level.

## Quick Start

```bash
git clone https://github.com/dachony/dns-supreme.git
cd dns-supreme
docker compose up -d
```

Open **http://localhost:5380** and login with `admin` / `admin`.

## Requirements

- Docker and Docker Compose
- Ports: 5380 (web UI), 53535 (DNS — configurable)

## What's Included

### DNS Server
- DNS over UDP/TCP (port 53)
- DNS-over-TLS (port 853)
- DNS-over-HTTPS (port 8443)
- DNS-over-QUIC (port 8853)
- Caching with configurable TTL
- Authoritative zones with full record management

### DNS Filtering
- 22+ community blocklists (Hagezi, OISD, Steven Black, 1Hosts, AdGuard, etc.)
- Premium feed support (Kaspersky, Palo Alto, CrowdStrike, Fortinet, etc.)
- Custom feeds via URL
- Per-category toggle (Ads, Malware, Adult, Social, Gambling, Tracking)
- Custom block/allow rules
- Per-device policies with overrides
- Global allowlist

### Network Protection
- Tor exit node blocking
- Spamhaus DROP (hijacked networks)
- Botnet C2 server blocking (Feodo Tracker)
- Malicious IP blocking (Emerging Threats)
- URLhaus malware distribution blocking
- Auto-refresh feeds (configurable interval)

### GeoIP Country Blocking
- Block DNS responses resolving to specific countries
- Auto-download GeoIP database (DB-IP, free)
- Searchable country picker with flags

### Security
- Fail2Ban — auto-blocks IPs after failed login attempts
- IP allowlist for management panel access
- MFA — TOTP (authenticator app) and email code
- SMTP integration for security alerts

### Certificates
- Self-signed certificate generation
- Certificate upload (PEM)
- Certificate export for client distribution
- ACME/Let's Encrypt integration with DNS-01 challenge
- Per-zone certificates

### Management
- Dashboard with real-time stats, charts, system metrics
- Query log with search, filters, and detail view
- DNS zone management with record editor
- Block page builder with live preview
- User management with roles (admin/viewer)
- Cluster support (primary/secondary)
- SMTP mail with notifications
- Full settings persistence (survives restarts)

## Docker Compose Ports

| Port | Service |
|------|---------|
| 5380 | Web UI and API |
| 53535 | DNS (UDP+TCP) |
| 8530 | DNS-over-TLS |
| 8553 | DNS-over-HTTPS |
| 8853 | DNS-over-QUIC |
| 8880 | Block page HTTP |
| 4443 | Block page HTTPS |

## Configuration

All configuration is done through the web UI at `http://localhost:5380`.

On first start:
1. Default admin user is created: `admin` / `admin` — **change this immediately**
2. Default zone `dnssupreme.local` is created automatically
3. Steven Black hosts blocklist is loaded by default
4. GeoIP database auto-downloads on first run

### Environment Variables (optional)

| Variable | Default | Description |
|----------|---------|-------------|
| `DNS_LISTEN_ADDR` | `0.0.0.0` | DNS listen address |
| `DNS_PORT` | `53` | DNS port |
| `DNS_FORWARDERS` | `8.8.8.8:53,1.1.1.1:53` | Upstream DNS servers |
| `DB_HOST` | `postgres` | PostgreSQL host |
| `DB_PORT` | `5432` | PostgreSQL port |
| `DB_USER` | `dnsupreme` | Database user |
| `DB_PASSWORD` | `dnsupreme` | Database password |
| `DB_NAME` | `dnsupreme` | Database name |
| `API_PORT` | `5380` | Web UI port |
| `GEOIP_DB_PATH` | auto-download | Path to GeoIP mmdb file |

## API

Health check (no auth): `GET /api/health`

All other endpoints require `Authorization: Bearer <token>` header. Get a token via `POST /api/auth/login`.

## Tech Stack

- **Backend**: Go 1.23, Gin, miekg/dns, PostgreSQL
- **Frontend**: Vue 3, TypeScript, Vite, Chart.js
- **Infrastructure**: Docker, multi-stage build

## License

MIT
