# DNS Supreme — TODO

Konkretni taskovi bazirani na analizi koda. Sortirani po prioritetu.

## Kritično (Bezbednost + Stabilnost)

- [x] **Rate limiting po client IP** — Sliding-window limiter (100 req/10s) u `processDNSMsg()`
- [x] **Persist JWT secret u bazi** — Secret se čuva u DB settings tabeli, preživljava restart
- [x] **CORS konfiguracija** — Eksplicitni AllowMethods i AllowHeaders
- [x] **AXFR ograničenje** — IP whitelist za zone transfer sa `SetAXFRAllowIPs()`
- [x] **Fail2Ban na auth endpoint-ima** — IsBanned check na login i mfaVerify

## Visok prioritet (Performanse)

- [x] **Async reverse hostname lookup** — 500ms context timeout umesto blokirajućeg poziva
- [x] **Parallel upstream forwarding** — Race-first paralelni upiti ka svim forwarderima
- [ ] **Radix tree za NetProtect CIDR matching** — `contains()` iterira SVE CIDR range-ove sekvencijalno za svaku IP proveru. Sa 500+ CIDR-ova ovo je bottleneck
- [ ] **Cache eviction O(N) → O(log N)** — `Cache.evictOldest()` iterira sve entries. Koristiti heap ili indeks
- [ ] **Filter result caching** — Isti domen se proverava kroz filter za svaki upit. Dodati LRU cache za filter odluke

## Srednji prioritet (Funkcionalnost)

- [x] **Query log retention cleanup** — Hourly cleanup, konfigurabilno preko RetentionDays
- [x] **DNSSEC response signing integracija** — Integrisano u zone query path
- [x] **Prometheus /metrics endpoint** — 9 metrika, text format, bez eksternih dependency-ja
- [x] **Audit logging** — DB tabela + API endpoint, loguje login, user CRUD, blocklist, fail2ban
- [ ] **Query log aggregacija** — Svaki DNS upit kreira full DB row (16+ kolona). Dodati opciju za hourly agregaciju po (domain, client_ip, blocked, rule)
- [x] **Cert expiration alerts** — System-metrics prikazuje dane do isteka sa warning flag-om

## Nizak prioritet (Poboljšanja)

- [x] **Konfigurabilni Cache TTL** — `CacheMinTTL`/`CacheMaxTTL` u config + env varijable
- [x] **DB connection pool tuning** — Konfigurabilno kroz `DB_MAX_OPEN_CONNS`/`DB_MAX_IDLE_CONNS`
- [ ] **Structured logging** — Svi logovi koriste `log.Printf()`. Prebaciti na `slog` za parsabilne logove
- [x] **Health check detalji** — Detaljni endpoint sa `db_ok`, `dns_ok`, `uptime_seconds`
- [x] **Graceful shutdown** — 10s timeout sa context cancellation na SIGTERM/SIGINT
- [ ] **DNSSEC key rotation** — Nema automatske ili manuelne rotacije ključeva
- [x] **NetProtect feed staleness tracking** — `LastFetchError` i `Stale` flag per kategorija
- [x] **Dockerfile HEALTHCHECK** — 30s interval, 5s timeout, 3 retries
- [ ] **WebSocket za real-time dashboard** — Dashboard trenutno koristi polling. Dodati SSE ili WebSocket za live podatke
