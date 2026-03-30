package api

import (
	"encoding/json"
	"log"
	"net/http"

	dnsserver "github.com/dachony/dns-supreme/internal/dns"
	"github.com/gin-gonic/gin"
)

func (s *Server) setupDNSSECRoutes(protected *gin.RouterGroup) {
	dnssec := protected.Group("/dnssec")
	{
		dnssec.GET("", s.listDNSSECKeys)
		dnssec.POST("/generate", s.generateDNSSECKey)
		dnssec.GET("/:zone", s.getDNSSECKey)
		dnssec.PUT("/:zone", s.toggleDNSSEC)
		dnssec.DELETE("/:zone", s.deleteDNSSECKey)
	}
}

func (s *Server) listDNSSECKeys(c *gin.Context) {
	keys := s.dnssec.ListKeys()
	c.JSON(http.StatusOK, keys)
}

type generateDNSSECReq struct {
	ZoneName string `json:"zone_name" binding:"required"`
}

func (s *Server) generateDNSSECKey(c *gin.Context) {
	var req generateDNSSECReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	key, err := s.dnssec.GenerateKey(req.ZoneName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	s.persistDNSSECKeys()
	c.JSON(http.StatusOK, key)
}

func (s *Server) getDNSSECKey(c *gin.Context) {
	zone := c.Param("zone")
	key := s.dnssec.GetKey(zone)
	if key == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no DNSSEC key for this zone"})
		return
	}
	c.JSON(http.StatusOK, key)
}

type toggleDNSSECReq struct {
	Enabled bool `json:"enabled"`
}

func (s *Server) toggleDNSSEC(c *gin.Context) {
	zone := c.Param("zone")
	var req toggleDNSSECReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.dnssec.SetEnabled(zone, req.Enabled)
	s.persistDNSSECKeys()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) deleteDNSSECKey(c *gin.Context) {
	zone := c.Param("zone")
	s.dnssec.RemoveKey(zone)
	s.persistDNSSECKeys()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) persistDNSSECKeys() {
	keys := s.dnssec.ListKeys()
	data, _ := json.Marshal(keys)
	s.db.SetSetting("dnssec_keys", string(data))
}

func (s *Server) restoreDNSSECKeys() {
	data := s.db.GetSetting("dnssec_keys")
	if data == "" {
		return
	}
	var keys []dnsserver.DNSSECKey
	if err := json.Unmarshal([]byte(data), &keys); err != nil {
		return
	}
	for _, k := range keys {
		if err := s.dnssec.RestoreKey(k); err != nil {
			log.Printf("[DNSSEC] Failed to restore key for %s: %v", k.ZoneName, err)
		}
	}
}
