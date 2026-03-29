# DNS-supreme — Dnevnik odluka

Ovde beležimo sve ključne arhitekturne i dizajnerske odluke.

---

## 2026-03-29 — Projekat pokrenut, definisani zahtevi

### Odlučeno:
- **Deployment:** Docker-first, ali mora raditi i bez Docker-a (standalone)
- **Razvoj:** Lokalno podizanje kroz Docker za pregled tokom razvoja
- **Baza:** PostgreSQL
- **Cluster:** Podrška za primarni + sekundarni DNS (HA)

### Zahtevi za skaliranje:
- 1.000–5.000 klijenata koji šalju DNS upite
- Infrastrukturni DNS server (ne samo kućna upotreba)

### DNS protokoli (svi obavezni):
- [x] DNS (UDP/TCP, port 53)
- [x] DNS over TLS (DoT, port 853)
- [x] DNS over HTTPS (DoH, port 443)
- [x] DNS over QUIC (DoQ, port 853/UDP)

### Funkcionalnosti:

#### DNS Core
- [ ] Rekurzivni resolver
- [ ] DNS forwarding (konfigurabilni forwarderi)
- [ ] Autoritativni DNS server (zone hosting)
- [ ] Zone transfer (AXFR/IXFR) — za cluster replikaciju
- [ ] DNSSEC podrška
- [ ] Dinamički DNS (DDNS)
- [ ] Primarni/sekundarni DNS cluster

#### Filtering
- [ ] Blockliste po kategorijama (ads, trackeri, malware, adult, gambling, social media...)
- [ ] Blockliste po geolokaciji (blokiranje po zemlji/regionu)
- [ ] Custom filter pravila (ručno dodavanje domena)
- [ ] Allowliste / override-ovi
- [ ] Per-device ili per-network politike
- [ ] Data feed-ovi sa eksternih repozitorijuma (GitHub liste, URL sources)
- [ ] Automatski update blocklista po rasporedu (cron/interval)

#### Block Page
- [ ] Prilagodljiva block stranica (custom HTML/CSS)
- [ ] Prikazuje se kad je domen blokiran
- [ ] Info o tome zašto je blokiran (kategorija, pravilo)
- [ ] Mogućnost override-a (allowlist request)

#### TLS / Sertifikati
- [ ] Self-signed sertifikati (generisanje i upload)
- [ ] Let's Encrypt integracija (ACME automatski)
- [ ] Podrška za eksterne CA servise
- [ ] HTTPS za Web UI
- [ ] TLS za DoT i DoH

#### Dashboard & UI
- [ ] Web UI za administraciju (HTTPS)
- [ ] Dashboard sa pregledom dozvoljenih i blokiranih upita
- [ ] Real-time statistike
- [ ] Top domains, top clients, query types
- [ ] Per-client statistike

#### Logovanje
- [ ] Query log (svi DNS upiti)
- [ ] Pretraga logova (po domenu, klijentu, vremenu, tipu, statusu)
- [ ] Retention politike za logove
- [ ] Export logova

#### API & Integracije
- [ ] REST API za sve operacije
- [ ] Autentifikacija i autorizacija (multi-user)

---

## Otvorena pitanja
- Programski jezik — TBD (predlog: Go)
- Frontend framework — TBD
- MVP scope / faziranje — TBD
