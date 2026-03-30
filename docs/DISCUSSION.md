# DNS-supreme — Diskusija i razvoj

## Verzije

### v1.0.0 — 2026-03-29
Prva production verzija. Sve faze (1-4) implementirane u jednom danu.

---

## Tech Stack (Zaključeno)
- **Backend:** Go 1.23
- **Frontend:** Vue 3 + Vite + TypeScript (bez UI kit-a, custom CSS variables)
- **Baza:** PostgreSQL 16
- **Deploy:** Docker Compose
- **DNS biblioteka:** miekg/dns
- **GeoIP:** DB-IP free (auto-download)
- **ACME:** golang.org/x/crypto/acme

## Implementirane faze

### Faza 1 (DNS engine)
- DNS server (UDP/TCP) sa forwarderima
- Steven Black hosts blocklist kao default
- Query log u PostgreSQL sa batch insert-om
- Web UI sa Vue 3
- Docker Compose deployment

### Faza 2 (Encrypcija + filtering)
- DNS-over-TLS (port 853)
- DNS-over-HTTPS (port 443, path /dns-query)
- DNS-over-QUIC (port 853/UDP)
- 22+ community blocklist katalog (Hagezi, OISD, Steven Black, 1Hosts, AdGuard, itd.)
- Premium feed podrška (Kaspersky, Palo Alto, CrowdStrike, Fortinet, abuse.ch, itd.)
- Kategorije sa toggle-ovima (Ads, Malware, Adult, Social, Gambling, Tracking)
- GeoIP country blocking sa searchable picker-om
- Network Protection (Tor, Spamhaus DROP, Botnet C2, Malicious IPs, URLhaus)
- Query log pretraga i statistike
- Dashboard sa real-time chartovima

### Faza 3 (Autoritativni DNS)
- Zone management (forward + reverse)
- Record editor (A, AAAA, CNAME, MX, TXT, NS, SRV, PTR, CAA)
- DNSSEC signing per-zone
- Primary/secondary cluster konfiguracija
- Primary domain koncept sa auto-zone kreacijom

### Faza 4 (Security + production)
- Block page sa visual builder-om i live preview
- Self-signed i ACME/Let's Encrypt certifikati
- Per-zone certifikati
- Certificate export za distribuciju klijentima
- Per-device filtering policies
- Multi-user auth sa roles (admin/viewer)
- TOTP i Email MFA
- Fail2Ban sa IP banning-om
- IP access control za management panel
- SMTP mailer sa security alert notifikacijama
- Kompletna persistence u PostgreSQL
- Graceful restart (SIGHUP) za TLS reload
- Health check endpoint

## Arhitektura

Videti `docs/ARCHITECTURE.md` za detalje.
