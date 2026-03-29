package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type blockPageReq struct {
	HTML string `json:"html" binding:"required"`
}

func (s *Server) getBlockPageTemplate(c *gin.Context) {
	html := ""
	if s.blockPage != nil {
		html = s.blockPage.GetCustomTemplate()
	}
	c.JSON(http.StatusOK, gin.H{"html": html})
}

func (s *Server) setBlockPageTemplate(c *gin.Context) {
	var req blockPageReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if s.blockPage == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "block page server not available"})
		return
	}
	if err := s.blockPage.SetCustomTemplate(req.HTML); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// --- Forwarders ---

type forwarderEntry struct {
	Address  string `json:"address"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
}

func (s *Server) getForwarders(c *gin.Context) {
	fwds := s.dns.GetForwarders()
	entries := make([]forwarderEntry, len(fwds))
	for i, f := range fwds {
		entries[i] = forwarderEntry{
			Address:  f,
			Name:     friendlyName(f),
			Protocol: "DNS (UDP/TCP)",
		}
	}
	c.JSON(http.StatusOK, entries)
}

type setForwardersReq struct {
	Forwarders []string `json:"forwarders" binding:"required"`
}

func (s *Server) setForwarders(c *gin.Context) {
	var req setForwardersReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(req.Forwarders) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "at least one forwarder required"})
		return
	}
	s.dns.SetForwarders(req.Forwarders)
	c.JSON(http.StatusOK, gin.H{"status": "ok", "count": len(req.Forwarders)})
}

func friendlyName(addr string) string {
	known := map[string]string{
		"8.8.8.8:53":       "Google Public DNS",
		"8.8.4.4:53":       "Google Public DNS (secondary)",
		"1.1.1.1:53":       "Cloudflare DNS",
		"1.0.0.1:53":       "Cloudflare DNS (secondary)",
		"9.9.9.9:53":       "Quad9 DNS",
		"149.112.112.112:53": "Quad9 DNS (secondary)",
		"208.67.222.222:53": "OpenDNS",
		"208.67.220.220:53": "OpenDNS (secondary)",
		"94.140.14.14:53":  "AdGuard DNS",
		"94.140.15.15:53":  "AdGuard DNS (secondary)",
	}
	if name, ok := known[addr]; ok {
		return name
	}
	return "Custom"
}
