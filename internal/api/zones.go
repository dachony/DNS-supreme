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

	nameservers := req.Nameservers
	if len(nameservers) == 0 {
		nameservers = []string{"ns1." + req.Name, "ns2." + req.Name}
	}

	// --- SOA ---
	soaValue := fmt.Sprintf("%s %s %d 3600 900 604800 300",
		req.PrimaryNS, req.AdminEmail, zone.SOASerial)
	s.db.CreateRecord(&db.DNSRecord{
		ZoneID: zone.ID, Name: "@", Type: "SOA", Value: soaValue, TTL: req.TTL,
	})

	// --- NS records ---
	for _, ns := range nameservers {
		s.db.CreateRecord(&db.DNSRecord{
			ZoneID: zone.ID, Name: "@", Type: "NS", Value: ns, TTL: req.TTL,
		})
	}

	// --- A records for nameservers (glue records) ---
	// Only if nameservers are subdomains of this zone
	for i, ns := range nameservers {
		if len(ns) > len(req.Name) && ns[len(ns)-len(req.Name):] == req.Name {
			sub := ns[:len(ns)-len(req.Name)-1] // strip ".zone"
			glueIP := fmt.Sprintf("127.0.0.%d", i+1) // placeholder — user should update
			s.db.CreateRecord(&db.DNSRecord{
				ZoneID: zone.ID, Name: sub, Type: "A", Value: glueIP, TTL: req.TTL,
			})
		}
	}

	// --- DNSSEC (auto-generate key and create DS/DNSKEY) ---
	dnssecKey, err := s.dnssec.GenerateKey(req.Name)
	if err == nil && dnssecKey != nil {
		// Store DNSKEY as a record in the zone
		s.db.CreateRecord(&db.DNSRecord{
			ZoneID: zone.ID, Name: "@", Type: "DNSKEY",
			Value: dnssecKey.DNSKEYRecord, TTL: req.TTL,
		})
		// Store DS record reference
		s.db.CreateRecord(&db.DNSRecord{
			ZoneID: zone.ID, Name: "@", Type: "DS",
			Value: dnssecKey.DSRecord, TTL: req.TTL,
		})
	}

	// --- CAA (Let's Encrypt default) ---
	s.db.CreateRecord(&db.DNSRecord{
		ZoneID: zone.ID, Name: "@", Type: "CAA",
		Value: "0 issue \"letsencrypt.org\"", TTL: req.TTL,
	})

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
