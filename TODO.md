# DNS Supreme — TODO

Svi taskovi iz inicijalne analize koda su završeni.

## Kritično (Bezbednost + Stabilnost) — 5/5

- [x] **Rate limiting po client IP** — Sliding-window limiter (100 req/10s) u `processDNSMsg()`
- [x] **Persist JWT secret u bazi** — Secret se čuva u DB settings tabeli, preživljava restart
- [x] **CORS konfiguracija** — Eksplicitni AllowMethods i AllowHeaders
- [x] **AXFR ograničenje** — IP whitelist za zone transfer sa `SetAXFRAllowIPs()`
- [x] **Fail2Ban na auth endpoint-ima** — IsBanned check na login i mfaVerify

## Visok prioritet (Performanse) — 5/5

- [x] **Async reverse hostname lookup** — 500ms context timeout umesto blokirajućeg poziva
- [x] **Parallel upstream forwarding** — Race-first paralelni upiti ka svim forwarderima
- [x] **Radix tree za NetProtect CIDR matching** — IPMatcher sa sorted prefix binary search, O(log N)
- [x] **Cache eviction O(log N)** — Min-heap sa `container/heap` umesto O(N) linear scan
- [x] **Filter result caching** — LRU cache (50K entries, 60s TTL) sa automatskom invalidacijom

## Srednji prioritet (Funkcionalnost) — 6/6

- [x] **Query log retention cleanup** — Hourly cleanup, konfigurabilno preko RetentionDays
- [x] **DNSSEC response signing integracija** — Integrisano u zone query path
- [x] **Prometheus /metrics endpoint** — 9 metrika, text format, bez eksternih dependency-ja
- [x] **Audit logging** — DB tabela + API endpoint, loguje login, user CRUD, blocklist, fail2ban
- [x] **Query log aggregacija** — Hourly rollup za logove starije od 24h
- [x] **Cert expiration alerts** — System-metrics prikazuje dane do isteka sa warning flag-om

## Nizak prioritet (Poboljšanja) — 9/9

- [x] **Konfigurabilni Cache TTL** — `CacheMinTTL`/`CacheMaxTTL` u config + env varijable
- [x] **DB connection pool tuning** — Konfigurabilno kroz `DB_MAX_OPEN_CONNS`/`DB_MAX_IDLE_CONNS`
- [x] **Structured logging** — Svi logovi migrirani na `log/slog` sa JSON output-om
- [x] **Health check detalji** — Detaljni endpoint sa `db_ok`, `dns_ok`, `uptime_seconds`
- [x] **Graceful shutdown** — 10s timeout sa context cancellation na SIGTERM/SIGINT
- [x] **DNSSEC key rotation** — API endpoint `POST /dnssec/:zone/rotate` sa audit logom
- [x] **NetProtect feed staleness tracking** — `LastFetchError` i `Stale` flag per kategorija
- [x] **Dockerfile HEALTHCHECK** — 30s interval, 5s timeout, 3 retries
- [x] **WebSocket/SSE za real-time dashboard** — SSE sa 5s broadcast, auto-reconnect na frontendu
