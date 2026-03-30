# DNS Supreme v1.0.0 — Arhitektura

## Pregled

```
                    ┌─────────────────────────────────────┐
                    │           Docker Compose             │
                    │                                      │
  Klijenti ───────> │  ┌──────────────────────────────┐   │
  (port 53)         │  │       DNS Supreme (Go)        │   │
                    │  │                                │   │
  Browser ────────> │  │  ┌─────────┐  ┌───────────┐  │   │
  (port 5380)       │  │  │  DNS    │  │  API      │  │   │
                    │  │  │  Server │  │  Server   │  │   │
  HTTPS ──────────> │  │  │  :53   │  │  :5380    │  │   │
  (port 443)        │  │  └────┬────┘  └─────┬─────┘  │   │
                    │  │       │              │        │   │
                    │  │  ┌────▼──────────────▼─────┐  │   │
                    │  │  │    Filter Engine         │  │   │
                    │  │  │  (blocklists, policies,  │  │   │
                    │  │  │   netprotect, geoip)     │  │   │
                    │  │  └────────────┬────────────┘  │   │
                    │  │               │               │   │
                    │  │  ┌────────────▼────────────┐  │   │
                    │  │  │    Block Page Server     │  │   │
                    │  │  │    :80 / :443            │  │   │
                    │  │  └─────────────────────────┘  │   │
                    │  └──────────────┬────────────────┘   │
                    │                 │                     │
                    │  ┌──────────────▼────────────────┐   │
                    │  │     PostgreSQL 16              │   │
                    │  │     (query_log, users,         │   │
                    │  │      zones, dns_records,       │   │
                    │  │      blocklists, settings)     │   │
                    │  └───────────────────────────────┘   │
                    └─────────────────────────────────────┘
```

## Tech Stack

- **Backend:** Go 1.23, Gin web framework
- **DNS:** miekg/dns (de facto standard, koristi ga CoreDNS)
- **Frontend:** Vue 3 + TypeScript + Vite + Chart.js
- **Baza:** PostgreSQL 16
- **GeoIP:** DB-IP free (MMDB format, auto-download)
- **ACME:** golang.org/x/crypto/acme
- **Deploy:** Docker multi-stage build

## Backend moduli

### DNS Server (`internal/dns/`)
- `server.go` — UDP/TCP/DoT/DoH/DoQ listeneri, `processDNSMsg()` pipeline
- `cache.go` — LRU DNS cache sa TTL i Flush()

**Pipeline:** Filter Check → Zone Lookup → Cache → Forward → Response Filter (NetProtect) → Cache Store → Return

### Filter Engine (`internal/filter/`)
- `filter.go` — domain matching (exact + parent), categories, allowlist, custom blocks
- `policies.go` — per-device policy override (disabled categories, custom blocks/allows)
- `netprotect.go` — IP-based threat feeds (Tor, Spamhaus, Botnet, Malicious, URLhaus), auto-refresh
- `geoip.go` — MMDB reader, auto-download DB-IP free database

### API Server (`internal/api/`)
- `api.go` — Gin router, auth middleware, login sa fail2ban, email MFA
- `fail2ban.go` — rate limiting, IP banning, access control allowlist
- `netprotect.go` — Network Protection API
- `cluster.go` — hostname, primary domain, cluster config
- `serversettings.go` — DNS settings, forwarders
- `certs.go` — TLS generate/upload/export, ACME
- `mail.go` — SMTP config, test email, notifications
- `policies.go` — device policy CRUD
- `settings.go` — block page template
- `zones.go` — zone + record CRUD, DNSSEC

### Ostali moduli
- `internal/db/` — PostgreSQL, schema, query log batching, KV settings
- `internal/auth/` — JWT, bcrypt, TOTP, email MFA codes
- `internal/mailer/` — SMTP (STARTTLS/SSL/plain), email templates
- `internal/certs/` — self-signed, ACME/Let's Encrypt sa DNS-01 solver
- `internal/blockpage/` — HTTP/HTTPS block page server, Go templates
- `internal/config/` — environment variable config loading

## DNS Query Pipeline

```
1. Klijent salje DNS upit (UDP/TCP/DoT/DoH/DoQ)
2. Filter check (domain-based):
   a. Per-device allows → ALLOW
   b. Global allowlist → ALLOW
   c. Per-device blocks → BLOCK
   d. Custom blocks → BLOCK
   e. Blocklists (sa category check) → BLOCK
3. Zone lookup (autoritativni odgovor) → RETURN
4. Cache check → RETURN cached
5. Forward to upstream
6. Response filter (IP-based):
   a. Network Protection feeds (Tor, Spamhaus, Botnet, Malicious, URLhaus) → BLOCK
   b. GeoIP country check → BLOCK
7. Cache store + return to client
```

## Frontend stranice

| Stranica | Fajl | Opis |
|----------|------|------|
| Login | `Login.vue` | Login + MFA (TOTP/email) |
| Dashboard | `Dashboard.vue` | Stats, system metrike, chart, protection bar |
| DNS Zones | `Zones.vue` | Zone lista, record editor, DNSSEC, primary badge |
| DNS Filtering | `Blocklists.vue` | 7 tabova: Services, Active Lists, Community, Premium, Custom, Rules, Network Protection |
| Query Log | `QueryLog.vue` | Log tabela, detail modal, filters, pagination |
| Settings | `Settings.vue` | 9 tabova: Identity, Cluster, DNS, Forwarders, Certs, Block Page, Logs, Mail, Users |

## Baza podataka

| Tabela | Opis |
|--------|------|
| `query_log` | DNS upiti (batch insert) |
| `blocklists` | Aktivne liste (name, url, category, count) |
| `users` | Korisnici (username, hash, role, mfa) |
| `zones` | DNS zone (name, type, soa_serial, ttl) |
| `dns_records` | DNS zapisi (zone_id, name, type, value, ttl) |
| `settings` | KV store za sve konfiguracije |

## Persistence (settings KV)

Svi settings se cuvaju u `settings` tabeli kao key-value:
hostname, primary_domain, forwarders, server_settings, np_enabled_categories, geo_blocked_countries, custom_blocks, allowlist, device_policies, block_page_html, mail_config, mail_notifications, fail2ban_settings, allowed_ips, acme_config, cluster_config

## Portovi

| Port | Servis |
|------|--------|
| 53 | DNS (UDP+TCP) |
| 853 | DNS-over-TLS |
| 853/UDP | DNS-over-QUIC (RFC 9250) |
| 80 | Block page HTTP |
| 443 | Block page HTTPS + DoH (/dns-query) |
| 5380 | Management panel |
