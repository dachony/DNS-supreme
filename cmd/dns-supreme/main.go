package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"encoding/json"

	"github.com/dachony/dns-supreme/internal/api"
	"github.com/dachony/dns-supreme/internal/blockpage"
	"github.com/dachony/dns-supreme/internal/certs"
	"github.com/dachony/dns-supreme/internal/config"
	"github.com/dachony/dns-supreme/internal/db"
	dnsserver "github.com/dachony/dns-supreme/internal/dns"
	"github.com/dachony/dns-supreme/internal/filter"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("=== DNS-supreme v1.0.0 ===")

	cfg := config.LoadFromEnv()

	// Initialize database
	database, err := db.New(cfg.Database, cfg.Logging)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer database.Close()

	// Initialize filter engine
	filterEngine := filter.NewEngine()

	// Load persisted blocklists from database, fallback to defaults
	loadPersistedBlocklists(database, filterEngine)
	loadPersistedFilterSettings(database, filterEngine)

	// Initialize network protection engine
	netProtect := filter.NewNetProtectEngine()

	// Initialize GeoIP for country blocking
	geoReader, err := filter.NewGeoIPReader("/app/data")
	if err != nil {
		log.Printf("[GeoIP] Warning: GeoIP not available: %v", err)
		log.Println("[GeoIP] Country blocking will be disabled. Set GEOIP_DB_PATH or ensure network access for auto-download.")
	} else {
		netProtect.SetGeoLookup(geoReader.Lookup)
		defer geoReader.Close()
		log.Println("[GeoIP] Country blocking is available")
	}

	// Load persisted network protection settings
	loadPersistedNpSettings(database, netProtect)

	netProtect.Start()

	// Initialize TLS
	certFile := os.Getenv("TLS_CERT_FILE")
	keyFile := os.Getenv("TLS_KEY_FILE")
	tlsConfig, err := certs.LoadOrGenerateTLS(certFile, keyFile)
	if err != nil {
		log.Printf("[TLS] Warning: TLS not available: %v", err)
		tlsConfig = nil
	}

	// Create log function
	logFn := func(result *dnsserver.QueryResult) {
		if !cfg.Logging.QueryLog {
			return
		}
		database.LogQuery(db.QueryLog{
			Timestamp:      result.Timestamp,
			ClientIP:       result.ClientIP,
			ClientHostname: result.ClientHostname,
			Domain:         result.Domain,
			QueryType:  result.QueryType,
			Blocked:    result.Blocked,
			BlockRule:  result.BlockRule,
			ResponseIP: result.ResponseIP,
			LatencyMs:  float64(result.Latency.Microseconds()) / 1000.0,
			Upstream:   result.Upstream,
			Protocol:   result.Protocol,
		})
	}

	// Start DNS server
	dnsServer := dnsserver.NewServer(cfg.DNS, filterEngine.Check, logFn, tlsConfig)

	// Restore persisted forwarders
	if data := database.GetSetting("forwarders"); data != "" {
		var fwds []string
		if json.Unmarshal([]byte(data), &fwds) == nil && len(fwds) > 0 {
			dnsServer.SetForwarders(fwds)
			log.Printf("[Persistence] Restored %d forwarders", len(fwds))
		}
	}

	// Connect zone lookup to database
	dnsServer.SetZoneLookup(func(name, rtype string) ([]db.DNSRecord, error) {
		return database.FindRecords(name, rtype)
	})

	// Connect zone transfer data function
	dnsServer.SetZoneDataFunc(func(zoneName string) (*db.Zone, []db.DNSRecord, error) {
		zone, err := database.GetZoneByName(zoneName)
		if err != nil {
			return nil, nil, err
		}
		records, err := database.ListRecords(zone.ID)
		if err != nil {
			return nil, nil, err
		}
		return zone, records, nil
	})

	// Start block page server (HTTP on port 80, HTTPS+DoH on port 443)
	blockPageServer := blockpage.NewServer(
		cfg.BlockPage.ListenAddr,
		cfg.BlockPage.HTTPPort,
		cfg.BlockPage.HTTPSPort,
		tlsConfig,
	)
	blockPageServer.SetDoHHandler(dnsServer.DoHHandler())
	blockPageServer.Start()

	// Connect block page to DNS server
	blockPageIP := os.Getenv("BLOCK_PAGE_IP")
	if blockPageIP == "" {
		blockPageIP = "0.0.0.0" // container IP — will be set via env in docker-compose
	}
	dnsServer.SetBlockPage(blockPageIP, func(domain, reason string) {
		blockPageServer.RecordBlock(domain, reason)
	})

	// Connect network protection response filter to DNS server
	dnsServer.SetResponseFilter(func(ip string) (bool, string, string) {
		return netProtect.CheckIP(ip)
	})

	if err := dnsServer.Start(); err != nil {
		log.Fatalf("Failed to start DNS server: %v", err)
	}
	defer dnsServer.Shutdown()

	// Start API server
	apiServer := api.NewServer(cfg.API, database, filterEngine, netProtect, blockPageServer, dnsServer)
	if err := apiServer.Start(); err != nil {
		log.Fatalf("Failed to start API server: %v", err)
	}

	// Auto-create default primary zone if no zones exist
	zones, _ := database.ListZones()
	if len(zones) == 0 {
		log.Println("[Setup] No zones found, creating default primary zone: dnssupreme.local")
		defaultZone := &db.Zone{Name: "dnssupreme.local", Type: "primary", TTL: 3600}
		if err := database.CreateZone(defaultZone); err == nil {
			database.CreateRecord(&db.DNSRecord{
				ZoneID: defaultZone.ID, Name: "@", Type: "SOA",
				Value: "ns1.dnssupreme.local admin.dnssupreme.local 1 3600 900 604800 300", TTL: 3600,
			})
			database.CreateRecord(&db.DNSRecord{
				ZoneID: defaultZone.ID, Name: "@", Type: "NS",
				Value: "ns1.dnssupreme.local", TTL: 3600,
			})
			log.Println("[Setup] Default zone 'dnssupreme.local' created with SOA and NS records")
		}
	}

	log.Println("DNS-supreme is ready!")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for s := range sig {
		if s == syscall.SIGHUP {
			log.Println("[Restart] SIGHUP received — reloading TLS and restarting DNS...")
			// Reload TLS certificates
			newTLS, err := certs.LoadOrGenerateTLS(certFile, keyFile)
			if err == nil && newTLS != nil {
				dnsServer.ReloadTLS(newTLS)
				log.Println("[Restart] TLS certificates reloaded")
			}
			log.Println("[Restart] Restart complete")
			continue
		}
		break // SIGINT or SIGTERM
	}

	log.Println("Shutting down...")
}

func loadDefaultBlocklists(engine *filter.Engine) {
	type listDef struct {
		url      string
		category filter.Category
	}
	lists := map[string]listDef{
		"stevenblack-hosts": {"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", filter.CategoryAds},
	}

	if url := os.Getenv("BLOCKLIST_ADS"); url != "" {
		lists["ads-extra"] = listDef{url, filter.CategoryAds}
	}
	if url := os.Getenv("BLOCKLIST_MALWARE"); url != "" {
		lists["malware"] = listDef{url, filter.CategoryMalware}
	}

	for name, def := range lists {
		go func(n string, d listDef) {
			for i := 0; i < 3; i++ {
				if err := engine.AddList(n, d.url, d.category); err != nil {
					log.Printf("[Filter] Failed to load list '%s' (attempt %d): %v", n, i+1, err)
					time.Sleep(5 * time.Second)
					continue
				}
				return
			}
			log.Printf("[Filter] Giving up on list '%s'", n)
		}(name, def)
	}
}

func loadPersistedBlocklists(database *db.Database, engine *filter.Engine) {
	saved, err := database.GetBlocklistsFull()
	if err != nil || len(saved) == 0 {
		log.Println("[Persistence] No saved blocklists, loading defaults")
		loadDefaultBlocklists(engine)
		return
	}

	log.Printf("[Persistence] Loading %d saved blocklists from database", len(saved))
	for _, bl := range saved {
		go func(name, url string, cat string) {
			for i := 0; i < 3; i++ {
				if err := engine.AddList(name, url, filter.Category(cat)); err != nil {
					log.Printf("[Filter] Failed to load list '%s' (attempt %d): %v", name, i+1, err)
					time.Sleep(5 * time.Second)
					continue
				}
				return
			}
			log.Printf("[Filter] Giving up on list '%s'", name)
		}(bl.Name, bl.URL, bl.Category)
	}
}

func loadPersistedNpSettings(database *db.Database, np *filter.NetProtectEngine) {
	// Load enabled NP categories
	if data := database.GetSetting("np_enabled_categories"); data != "" {
		var enabled []string
		if json.Unmarshal([]byte(data), &enabled) == nil {
			for _, id := range enabled {
				np.SetCategoryEnabled(id, true)
			}
			log.Printf("[Persistence] Restored %d network protection categories", len(enabled))
		}
	}

	// Load geo-blocked countries
	if data := database.GetSetting("geo_blocked_countries"); data != "" {
		var countries []string
		if json.Unmarshal([]byte(data), &countries) == nil {
			np.SetGeoBlocked(countries)
			log.Printf("[Persistence] Restored %d geo-blocked countries", len(countries))
		}
	}
}

func loadPersistedFilterSettings(database *db.Database, engine *filter.Engine) {
	// Custom blocks
	if data := database.GetSetting("custom_blocks"); data != "" {
		var blocks map[string]string
		if json.Unmarshal([]byte(data), &blocks) == nil {
			for domain, reason := range blocks {
				engine.AddCustomBlock(domain, reason)
			}
			log.Printf("[Persistence] Restored %d custom block rules", len(blocks))
		}
	}

	// Allowlist
	if data := database.GetSetting("allowlist"); data != "" {
		var list []string
		if json.Unmarshal([]byte(data), &list) == nil {
			for _, domain := range list {
				engine.AddAllowlistDomain(domain)
			}
			log.Printf("[Persistence] Restored %d allowlist entries", len(list))
		}
	}
}
