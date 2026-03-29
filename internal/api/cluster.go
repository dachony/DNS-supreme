package api

import (
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
)

// In-memory settings store (production would persist to DB)
var (
	hostnameStore = "dns-supreme"
	clusterStore  = clusterConfig{
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
	settingsMu.RLock()
	defer settingsMu.RUnlock()
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
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
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
	c.JSON(http.StatusOK, gin.H{"status": "ok", "message": "Cluster settings saved. Restart to apply."})
}
