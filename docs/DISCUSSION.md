# DNS-supreme — Diskusija i otvorena pitanja

## Zaključene diskusije

### 2026-03-29 — Tech Stack
**Odlučeno:**
- **Backend:** Go
- **Frontend:** Vue 3 + Vite + TypeScript
- **UI kit:** TBD (Naive UI ili PrimeVue — odlučujemo kad krenemo sa UI)
- **Baza:** PostgreSQL
- **Deploy:** Docker-first, standalone later

**Razlozi:**
- Go — dokazan za DNS (CoreDNS), single binary, mali footprint, odličan networking
- Vue — čistiji za admin dashboard, manji bundle, manje boilerplate-a, AdGuard Home ga koristi

---

## Otvorena pitanja

### 1. MVP scope / faziranje
Predlog faza:
- **Faza 1:** DNS engine (UDP/TCP) + forwarderi + basic blockliste + query log + minimalan web UI + Docker compose
- **Faza 2:** DoT, DoH, DoQ + kategorije blocklista + geo-blocking + pretraga logova + statistike
- **Faza 3:** Autoritativni DNS + zone management + primary/secondary cluster + DNSSEC
- **Faza 4:** Block page + sertifikati (self-signed, Let's Encrypt) + per-device politike + multi-user auth + standalone binary

Da li je ovaj redosled OK?

### 2. UI kit
Naive UI vs PrimeVue — odlučujemo kad krenemo sa frontend-om.

### 3. Go DNS biblioteka
Kandidati:
- `miekg/dns` (github.com/miekg/dns) — de facto standard, koristi ga CoreDNS
- Custom implementacija — samo ako miekg ne pokrije sve potrebe
