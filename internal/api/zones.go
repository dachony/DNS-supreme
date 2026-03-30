package api

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/dachony/dns-supreme/internal/db"
	"github.com/gin-gonic/gin"
)

func (s *Server) setupZoneRoutes(protected *gin.RouterGroup) {
	zones := protected.Group("/zones")
	{
		zones.GET("", s.listZones)
		zones.POST("", s.createZone)
		zones.GET("/:id", s.getZone)
		zones.DELETE("/:id", s.deleteZone)

		zones.GET("/:id/records", s.listRecords)
		zones.POST("/:id/records", s.createRecord)
		zones.PUT("/:id/records/:rid", s.updateRecord)
		zones.DELETE("/:id/records/:rid", s.deleteRecord)
	}
}

func (s *Server) listZones(c *gin.Context) {
	zones, err := s.db.ListZones()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// Enrich with record count
	type zoneInfo struct {
		db.Zone
		RecordCount int  `json:"record_count"`
		DNSSECSigned bool `json:"dnssec_signed"`
	}
	result := make([]zoneInfo, len(zones))
	for i, z := range zones {
		records, _ := s.db.ListRecords(z.ID)
		signed := s.dnssec.GetKey(z.Name) != nil
		result[i] = zoneInfo{Zone: z, RecordCount: len(records), DNSSECSigned: signed}
	}
	c.JSON(http.StatusOK, result)
}

type createZoneReq struct {
	Name         string `json:"name" binding:"required"`
	Type         string `json:"type"`
	TTL          int    `json:"ttl"`
	PrimaryNS    string `json:"primary_ns"`
	AdminEmail   string `json:"admin_email"`
	Nameservers  []string `json:"nameservers"`
}

func (s *Server) createZone(c *gin.Context) {
	var req createZoneReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Type == "" {
		req.Type = "primary"
	}
	if req.TTL == 0 {
		req.TTL = 3600
	}
	if req.PrimaryNS == "" {
		req.PrimaryNS = "ns1." + req.Name
	}
	if req.AdminEmail == "" {
		req.AdminEmail = "admin." + req.Name
	}

	zone := &db.Zone{Name: req.Name, Type: req.Type, TTL: req.TTL}
	if err := s.db.CreateZone(zone); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "zone already exists"})
		return
	}

	// --- SOA ---
	soaValue := fmt.Sprintf("%s %s %d 3600 900 604800 300",
		req.PrimaryNS, req.AdminEmail, zone.SOASerial)
	s.db.CreateRecord(&db.DNSRecord{
		ZoneID: zone.ID, Name: "@", Type: "SOA", Value: soaValue, TTL: req.TTL,
	})

	// --- NS record (primary nameserver) ---
	s.db.CreateRecord(&db.DNSRecord{
		ZoneID: zone.ID, Name: "@", Type: "NS", Value: req.PrimaryNS, TTL: req.TTL,
	})

	// Auto-add secondary NS if cluster is configured
	settingsMu.RLock()
	clusterRole := clusterStore.Role
	clusterPeer := clusterStore.PeerAddress
	settingsMu.RUnlock()
	if clusterRole != "standalone" && clusterPeer != "" {
		secondaryNS := "ns2." + req.Name
		s.db.CreateRecord(&db.DNSRecord{
			ZoneID: zone.ID, Name: "@", Type: "NS", Value: secondaryNS, TTL: req.TTL,
		})
	}

	// Additional nameservers if explicitly provided
	for _, ns := range req.Nameservers {
		if ns != req.PrimaryNS {
			s.db.CreateRecord(&db.DNSRecord{
				ZoneID: zone.ID, Name: "@", Type: "NS", Value: ns, TTL: req.TTL,
			})
		}
	}

	c.JSON(http.StatusCreated, zone)
}

func (s *Server) getZone(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	zone, err := s.db.GetZone(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "zone not found"})
		return
	}

	records, _ := s.db.ListRecords(id)

	// Get DNSSEC info
	dnssecKey := s.dnssec.GetKey(zone.Name)

	c.JSON(http.StatusOK, gin.H{
		"zone":    zone,
		"records": records,
		"dnssec":  dnssecKey,
	})
}

func (s *Server) deleteZone(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	if err := s.db.DeleteZone(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

type createRecordReq struct {
	Name     string `json:"name" binding:"required"`
	Type     string `json:"type" binding:"required"`
	Value    string `json:"value" binding:"required"`
	TTL      int    `json:"ttl"`
	Priority int    `json:"priority"`
}

func (s *Server) listRecords(c *gin.Context) {
	zoneID, _ := strconv.Atoi(c.Param("id"))
	records, err := s.db.ListRecords(zoneID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, records)
}

func (s *Server) createRecord(c *gin.Context) {
	zoneID, _ := strconv.Atoi(c.Param("id"))
	var req createRecordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.TTL == 0 {
		req.TTL = 3600
	}

	record := &db.DNSRecord{
		ZoneID: zoneID, Name: req.Name, Type: req.Type,
		Value: req.Value, TTL: req.TTL, Priority: req.Priority,
	}
	if err := s.db.CreateRecord(record); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, record)
}

func (s *Server) updateRecord(c *gin.Context) {
	zoneID, _ := strconv.Atoi(c.Param("id"))
	rid, _ := strconv.Atoi(c.Param("rid"))
	var req createRecordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.TTL == 0 {
		req.TTL = 3600
	}

	record := &db.DNSRecord{
		ID: rid, ZoneID: zoneID, Name: req.Name, Type: req.Type,
		Value: req.Value, TTL: req.TTL, Priority: req.Priority,
	}
	if err := s.db.UpdateRecord(record); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, record)
}

func (s *Server) deleteRecord(c *gin.Context) {
	zoneID, _ := strconv.Atoi(c.Param("id"))
	rid, _ := strconv.Atoi(c.Param("rid"))
	if err := s.db.DeleteRecord(rid, zoneID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
