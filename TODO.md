# DNS Supreme — TODO

Konkretni taskovi bazirani na analizi koda. Sortirani po prioritetu.

## Kritično (Bezbednost + Stabilnost)

- [ ] **Rate limiting po client IP** — Nema ograničenja broja upita po klijentu. Ranjiv na DoS/amplification napade. Dodati sliding-window limiter u `processDNSMsg()` pre filtera
- [ ] **Persist JWT secret u bazi** — `auth/jwt.go` generiše random ključ pri svakom restartu, što invalidira sve tokene. Sačuvati ključ u DB pri prvom pokretanju
- [ ] **CORS konfiguracija** — `cors.Default()` dozvoljava sve origin-e. Postaviti eksplicitnu listu dozvoljenih origin-a
- [ ] **AXFR ograničenje** — `handleAXFR()` nema proveru ko sme da radi zone transfer. Dodati IP whitelist
- [ ] **Fail2Ban na auth endpoint-ima** — Login i MFA verifikacija nemaju rate limit. Brute-force je moguć

## Visok prioritet (Performanse)

- [ ] **Async reverse hostname lookup** — `resolveHostname()` je sinhroni poziv u query path-u (server.go:370). Ako je reverse DNS spor, blokira ceo upit. Prebaciti u async post-query logging
- [ ] **Parallel upstream forwarding** — `forward()` isprobava forwardere sekvencijalno sa 5s timeout-om. Sa 3 forwardera worst case je 15s. Implementirati race-first paralelne upite
- [ ] **Radix tree za NetProtect CIDR matching** — `contains()` iterira SVE CIDR range-ove sekvencijalno za svaku IP proveru. Sa 500+ CIDR-ova ovo je bottleneck
- [ ] **Cache eviction O(N) → O(log N)** — `Cache.evictOldest()` iterira sve entries. Koristiti heap ili indeks
- [ ] **Filter result caching** — Isti domen se proverava kroz filter za svaki upit. Dodati LRU cache za filter odluke

## Srednji prioritet (Funkcionalnost)

- [ ] **Query log retention cleanup** — `RetentionDays` je konfigurisan u DB ali se nikad ne koristi. Logovi rastu neograničeno. Implementirati periodični `DELETE FROM query_log WHERE timestamp < ...`
- [ ] **DNSSEC response signing integracija** — `SignResponse()` postoji ali se nigde ne poziva. Integrisati u `processDNSMsg()` za autoritativne zapise
- [ ] **Prometheus /metrics endpoint** — Nema standardnog metrics endpoint-a za monitoring. Dodati handler sa Prometheus text formatom
- [ ] **Audit logging** — Nema logova za sensitive operacije (user CRUD, policy izmene, blocklist update). Dodati audit tabelu
- [ ] **Query log aggregacija** — Svaki DNS upit kreira full DB row (16+ kolona). Dodati opciju za hourly agregaciju po (domain, client_ip, blocked, rule)
- [ ] **Cert expiration alerts** — Nema mehanizma upozorenja kad certifikat ističe. Dodati alert u system-metrics ako cert ističe za < 30 dana

## Nizak prioritet (Poboljšanja)

- [ ] **Konfigurabilni Cache TTL** — `minTTL` od 10s je hardkodiran (server.go:569). Dodati `CacheMinTTL`/`CacheMaxTTL` u config
- [ ] **DB connection pool tuning** — Fiksni pool (25 max, 5 idle). Učiniti konfigurabilnim kroz env varijable
- [ ] **Structured logging** — Svi logovi koriste `log.Printf()`. Prebaciti na `slog` za parsabilne logove
- [ ] **Health check detalji** — `/api/health` vraća samo string. Proširiti na `{dns_ok, db_ok, geoip_ok, cache_ok, upstreams}`
- [ ] **Graceful shutdown** — Nema signal handlera za SIGTERM/SIGINT. Dodati context cancellation sa čekanjem na in-flight upite
- [ ] **DNSSEC key rotation** — Nema automatske ili manuelne rotacije ključeva
- [ ] **NetProtect feed staleness tracking** — Ako feed fail-uje, samo se loguje. Dodati `last_fetch_error` i `last_successful_update_time` per kategorija
- [ ] **Dockerfile HEALTHCHECK** — Dodati `HEALTHCHECK CMD curl --fail http://localhost:5380/api/health || exit 1`
- [ ] **WebSocket za real-time dashboard** — Dashboard trenutno koristi polling. Dodati SSE ili WebSocket za live podatke
