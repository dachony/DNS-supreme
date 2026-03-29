package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/dachony/dns-supreme/internal/db"
	"github.com/gin-gonic/gin"
)

// In-memory settings store (production would persist to DB)
var (
	hostnameStore      = "ns1.dnssupreme.local"
	primaryDomainStore = "dnssupreme.local"
	clusterStore       = clusterConfig{
		Enabled: false,
		Role:    "standalone",
	}
	settingsMu sync.RWMutex
)

type clusterConfig struct {
	Enabled       bool     `json:"enabled"`
	Role          string   `json:"role"` // "standalone", "primary", "secondary"
	PeerAddress   string   `json:"peer_address"`
	PeerPort      int      `json:"peer_port"`
	SharedSecret  string   `json:"shared_secret"`
	SyncZones     bool     `json:"sync_zones"`
	SyncBlocklists bool   `json:"sync_blocklists"`
	SyncSettings  bool     `json:"sync_settings"`
	Peers         []peerInfo `json:"peers"`
}

type peerInfo struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Role     string `json:"role"`
	Status   string `json:"status"`
	LastSync string `json:"last_sync"`
}

// --- Hostname ---

func (s *Server) getHostname(c *gin.Context) {
	if v := s.db.GetSetting("hostname"); v != "" {
		c.JSON(http.StatusOK, gin.H{"hostname": v})
		return
	}
	c.JSON(http.StatusOK, gin.H{"hostname": hostnameStore})
}

type setHostnameReq struct {
	Hostname string `json:"hostname" binding:"required"`
}

func (s *Server) setHostname(c *gin.Context) {
	var req setHostnameReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	settingsMu.Lock()
	hostnameStore = req.Hostname
	settingsMu.Unlock()
	s.db.SetSetting("hostname", req.Hostname)
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// --- Primary Domain ---

func (s *Server) getPrimaryDomain(c *gin.Context) {
	if v := s.db.GetSetting("primary_domain"); v != "" {
		c.JSON(http.StatusOK, gin.H{"domain": v})
		return
	}
	c.JSON(http.StatusOK, gin.H{"domain": primaryDomainStore})
}

type setPrimaryDomainReq struct {
	Domain string `json:"domain" binding:"required"`
}

func (s *Server) setPrimaryDomain(c *gin.Context) {
	var req setPrimaryDomainReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	settingsMu.Lock()
	primaryDomainStore = req.Domain
	settingsMu.Unlock()
	s.db.SetSetting("primary_domain", req.Domain)

	// Auto-create zone if it doesn't exist
	s.ensurePrimaryZone(req.Domain)

	c.JSON(http.StatusOK, gin.H{"status": "ok", "domain": req.Domain})
}

func (s *Server) ensurePrimaryZone(domain string) {
	// Check if zone already exists
	zones, _ := s.db.ListZones()
	for _, z := range zones {
		if z.Name == domain {
			return // Already exists
		}
	}

	// Create the zone
	zone := &db.Zone{Name: domain, Type: "primary", TTL: 3600}
	if err := s.db.CreateZone(zone); err != nil {
		return
	}

	settingsMu.RLock()
	hostname := hostnameStore
	settingsMu.RUnlock()

	// SOA record
	soaValue := fmt.Sprintf("%s admin.%s %d 3600 900 604800 300",
		hostname, domain, zone.SOASerial)
	s.db.CreateRecord(&db.DNSRecord{
		ZoneID: zone.ID, Name: "@", Type: "SOA", Value: soaValue, TTL: 3600,
	})

	// NS records
	s.db.CreateRecord(&db.DNSRecord{
		ZoneID: zone.ID, Name: "@", Type: "NS", Value: hostname, TTL: 3600,
	})
}

// GetPrimaryDomain returns the current primary domain (used by main.go at startup)
func GetPrimaryDomain() string {
	settingsMu.RLock()
	defer settingsMu.RUnlock()
	return primaryDomainStore
}

// --- Cluster ---

func (s *Server) getCluster(c *gin.Context) {
	settingsMu.RLock()
	defer settingsMu.RUnlock()
	c.JSON(http.StatusOK, clusterStore)
}

func (s *Server) setCluster(c *gin.Context) {
	var req clusterConfig
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Role != "standalone" && req.Role != "primary" && req.Role != "secondary" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role must be 'standalone', 'primary', or 'secondary'"})
		return
	}
	settingsMu.Lock()
	clusterStore = req
	settingsMu.Unlock()
	if data, err := json.Marshal(req); err == nil {
		s.db.SetSetting("cluster_config", string(data))
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "message": "Cluster settings saved. Restart to apply."})
}

func (s *Server) getClusterFromDB() {
	if data := s.db.GetSetting("cluster_config"); data != "" {
		settingsMu.Lock()
		json.Unmarshal([]byte(data), &clusterStore)
		settingsMu.Unlock()
	}
}
