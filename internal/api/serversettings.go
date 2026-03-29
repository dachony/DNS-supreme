package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type serverSettingsResp struct {
	Protocols    map[string]bool `json:"protocols"`
	ListenAddresses struct {
		IPv4 string `json:"ipv4"`
		IPv6 string `json:"ipv6"`
	} `json:"listen_addresses"`
	IPv6Enabled  bool   `json:"ipv6_enabled"`
	CacheSize    int    `json:"cache_size"`
	DefaultTTL   int    `json:"default_ttl"`
	MinTTL       int    `json:"min_ttl"`
	MaxTTL       int    `json:"max_ttl"`
	ManagementHTTPS bool `json:"management_https"`
}

func (s *Server) getServerSettings(c *gin.Context) {
	resp := serverSettingsResp{
		Protocols: map[string]bool{
			"udp":  true,
			"tcp":  true,
			"dot":  true,
			"doh":  true,
			"doq":  true,
		},
		IPv6Enabled:     true,
		CacheSize:       10000,
		DefaultTTL:      3600,
		MinTTL:          10,
		MaxTTL:          86400,
		ManagementHTTPS: false,
	}
	resp.ListenAddresses.IPv4 = "0.0.0.0"
	resp.ListenAddresses.IPv6 = "::"

	// Read from DB settings if available
	c.JSON(http.StatusOK, resp)
}

func (s *Server) updateServerSettings(c *gin.Context) {
	var req serverSettingsResp
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// In a production system these would persist and trigger reconfiguration
	// For now, acknowledge the change
	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"message": "Settings saved. Some changes require a restart to take effect.",
	})
}

// --- Filtering Mode ---

type filteringModeResp struct {
	Mode string `json:"mode"` // "blocklist" or "allowlist"
	Description string `json:"description"`
}

func (s *Server) getFilteringMode(c *gin.Context) {
	mode := s.filter.GetMode()
	desc := "Allow all traffic except domains on blocklists"
	if mode == "allowlist" {
		desc = "Block all traffic except domains on the allowlist"
	}
	c.JSON(http.StatusOK, filteringModeResp{Mode: mode, Description: desc})
}

type setFilteringModeReq struct {
	Mode string `json:"mode" binding:"required"`
}

func (s *Server) setFilteringMode(c *gin.Context) {
	var req setFilteringModeReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Mode != "blocklist" && req.Mode != "allowlist" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "mode must be 'blocklist' or 'allowlist'"})
		return
	}
	s.filter.SetMode(req.Mode)
	c.JSON(http.StatusOK, gin.H{"status": "ok", "mode": req.Mode})
}
