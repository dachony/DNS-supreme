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

---

## 2026-04-04 — v2.0 release, Management HTTPS, ACME

### Odlučeno:
- **Management HTTPS** — port 53443, koristi `http.Server` direktno (ne Gin `RunTLS`) jer Gin ne može da pokrene dva listenera istovremeno
- **ACME DNS-01** — DNS server sada servira `_acme-challenge` TXT zapise iz baze; polling TXT propagacije svakih 10s (max 2 min)
- **Block page cert** — ne prepisuje `server.crt` ako već postoji; oba sertifikata koegzistiraju u `/app/certs/`
- **Docker restart** — koristi `SIGTERM` (ne `SIGHUP`) za potpuni restart kontejnera
- **certdata volume** — dodat u docker-compose da sertifikati prežive redeployment
- **Block Services** — novi tab u DNS Filtering za blokiranje servisa po kategorijama (ChatGPT, TikTok, itd.)

---

## 2026-04-28 — Docker DNS workaround, query log verifikacija

### Problem:
Docker-ov interni DNS resolver (`127.0.0.11:53`) pada sa timeout-om kada kontejner mapira port 53 na host. Ovo blokira sve HTTP fetch-eve iz aplikacije (blockliste, network protection feedovi, GeoIP download).

### Odlučeno:
- **Custom HTTP klijent** (`internal/filter/httpclient.go`) — `net.Resolver` koji direktno dials `8.8.8.8:53`, zaobilazi sistem resolver
- Svi eksterni HTTP pozivi u filter paketu (`filter.go`, `netprotect.go`, `geoip.go`) koriste `newHTTPClient()` umesto `&http.Client{}`
- Nije potrebno menjati `docker-compose.yml` niti DNS konfiguraciju hosta

### Deployment workflow:
- Remote host: `192.168.222.2`, user: `danijel`, app u `/home/danijel/DNS-supreme/`
- Host **nema `.git`** — deploy se radi ručno: `scp` izmenjenih fajlova + `sudo docker compose build && up -d`
- `update.sh` postoji ali zahteva git repo — nije primenjivo na ovom hostu
