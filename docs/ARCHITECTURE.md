# DNS-supreme — Arhitektura

## Tech Stack — ODLUČENO
- **Jezik:** Go
- **DNS biblioteka:** miekg/dns (de facto standard, koristi ga CoreDNS)
- **Baza podataka:** PostgreSQL
- **Web framework (API):** TBD (kandidati: Gin, Echo, Chi)
- **Frontend:** Vue 3 + Vite + TypeScript
- **UI kit:** TBD (Naive UI ili PrimeVue)
- **Cache:** In-memory (Go sync.Map / custom LRU)

## Skaliranje
- Target: 1.000–5.000 klijenata
- Cluster: primary + secondary DNS
- Zone transfer za sinhronizaciju

## Deployment
- **Primarni:** Docker (docker-compose sa app + postgres)
- **Sekundarni:** Standalone binary (bez Docker-a)
- **Cluster:** Docker compose sa primary + secondary instancama

## Visoki nivo arhitekture (predlog)

```
                        Klijenti (1000-5000)
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
         DNS (53)        DoT (853)      DoH/DoQ (443)
              │               │               │
              └───────────────┼───────────────┘
                              ▼
┌─────────────────────────────────────────────────────────┐
│                     DNS-supreme                          │
│                                                          │
│  ┌─────────────────────────────────────────────────┐    │
│  │              DNS Listener Layer                   │    │
│  │   UDP/TCP │ DoT (TLS) │ DoH (HTTPS) │ DoQ (QUIC)│    │
│  └────────────────────┬──────────────────────────────┘    │
│                       ▼                                  │
│  ┌─────────────────────────────────────────────────┐    │
│  │              Filter Pipeline                      │    │
│  │                                                   │    │
│  │  1. Allowlist check                               │    │
│  │  2. Custom rules                                  │    │
│  │  3. Blockliste (kategorije, geo)                  │    │
│  │  4. Data feed-ovi (GitHub, URL)                   │    │
│  │        ▼                                          │    │
│  │  BLOCKED → Block Page    ALLOWED → Resolver       │    │
│  └─────────────┬────────────────────┬────────────────┘    │
│                ▼                    ▼                     │
│  ┌──────────────────┐  ┌──────────────────────┐         │
│  │   Block Page     │  │   DNS Resolver /      │         │
│  │   Server         │  │   Forwarder           │         │
│  │                  │  │                        │         │
│  │  - Custom HTML   │  │  - Upstream forwarderi │         │
│  │  - Kategorija    │  │  - Cache               │         │
│  │  - Override req  │  │  - Rekurzija           │         │
│  └──────────────────┘  └──────────────────────┘         │
│                                                          │
│  ┌─────────────────────────────────────────────────┐    │
│  │              TLS / Certificate Manager            │    │
│  │                                                   │    │
│  │  - Self-signed generisanje                        │    │
│  │  - Let's Encrypt (ACME)                           │    │
│  │  - Custom CA upload                               │    │
│  │  - Auto-renewal                                   │    │
│  └─────────────────────────────────────────────────┘    │
│                                                          │
│  ┌─────────────────────────────────────────────────┐    │
│  │              Blocklist Manager                    │    │
│  │                                                   │    │
│  │  - Built-in liste (ads, malware, adult...)        │    │
│  │  - GitHub repo liste (URL import)                 │    │
│  │  - Custom data feed-ovi                           │    │
│  │  - Auto-update (cron/interval)                    │    │
│  │  - Custom ručne liste                             │    │
│  └─────────────────────────────────────────────────┘    │
│                                                          │
│  ┌─────────────────────────────────────────────────┐    │
│  │              Web UI (HTTPS)                       │    │
│  │                                                   │    │
│  │  - Dashboard (statistike, grafovi)                │    │
│  │  - Query log + pretraga                           │    │
│  │  - Blocklist management                           │    │
│  │  - Zone management                                │    │
│  │  - Certificate management                         │    │
│  │  - Server config                                  │    │
│  └──────────────────────┬────────────────────────────┘    │
│                         │                                │
│  ┌──────────────────────┴────────────────────────────┐   │
│  │              REST API Layer                        │   │
│  └──────────────────────┬────────────────────────────┘   │
│                         ▼                                │
│  ┌─────────────────────────────────────────────────┐    │
│  │              PostgreSQL                           │    │
│  │                                                   │    │
│  │  - Config & settings                              │    │
│  │  - DNS Zones & records                            │    │
│  │  - Query logs                                     │    │
│  │  - Blocklists & categories                        │    │
│  │  - Users & permissions                            │    │
│  │  - Certificates metadata                          │    │
│  └─────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘

        Cluster:
        ┌──────────┐    zone transfer    ┌──────────┐
        │ Primary  │ ◄────────────────► │Secondary │
        │  DNS     │    (AXFR/IXFR)     │  DNS     │
        │          │    config sync      │          │
        └──────────┘                    └──────────┘
```

## Blocklist Sources — Podržani formati

| Tip izvora | Primer |
|---|---|
| Built-in liste | Ugrađene ads/malware/adult liste |
| GitHub raw URL | `https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts` |
| GitHub repo | Ceo repo sa filter listama |
| Hosts format | `0.0.0.0 example.com` |
| Domain list | Jedan domen po liniji |
| AdBlock format | `\|\|example.com^` |
| Custom URL feed | Bilo koji URL koji vraća listu |

## Block Page mehanizam

Kad je domen blokiran:
1. DNS upit se odgovara sa IP adresom block page servera (lokalni HTTP server)
2. Block page server servira custom HTML stranicu
3. Stranica prikazuje: koji domen, zašto je blokiran, kategorija
4. Opciono: dugme za "request allowlist" (šalje zahtev adminu)

Za HTTPS blokiranje: koristi se self-signed cert za blokiran domen (ili NXDOMAIN odgovor kao alternativa — konfigurisano po želji).

## Certificate Management

```
┌─────────────────────────────────────┐
│        Certificate Manager          │
│                                     │
│  ┌─────────┐  ┌──────────────────┐ │
│  │Self-sign │  │  ACME Client     │ │
│  │Generator │  │  (Let's Encrypt) │ │
│  └─────────┘  └──────────────────┘ │
│  ┌─────────────────────────────────┐│
│  │  Custom cert upload (PEM/PFX)  ││
│  └─────────────────────────────────┘│
│  ┌─────────────────────────────────┐│
│  │  Auto-renewal & monitoring     ││
│  └─────────────────────────────────┘│
└─────────────────────────────────────┘

Koristi se za:
- Web UI (HTTPS)
- DoT listener
- DoH listener
- Block page HTTPS
```
