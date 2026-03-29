package api

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dachony/dns-supreme/internal/certs"
	"github.com/gin-gonic/gin"
)

type certInfo struct {
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	DNSNames  []string  `json:"dns_names"`
	IsCA      bool      `json:"is_ca"`
	CertFile  string    `json:"cert_file"`
	KeyFile   string    `json:"key_file"`
}

func (s *Server) getCerts(c *gin.Context) {
	certFile := os.Getenv("TLS_CERT_FILE")
	if certFile == "" {
		certFile = "/app/certs/server.crt"
	}

	info, err := readCertInfo(certFile)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status":  "self-signed (auto-generated)",
			"message": "Using auto-generated self-signed certificate",
		})
		return
	}

	c.JSON(http.StatusOK, info)
}

func (s *Server) generateSelfSigned(c *gin.Context) {
	certFile := "/app/certs/server.crt"
	keyFile := "/app/certs/server.key"

	os.MkdirAll("/app/certs", 0755)

	if err := certs.GenerateAndSave(certFile, keyFile); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	info, _ := readCertInfo(certFile)
	c.JSON(http.StatusOK, gin.H{
		"status":    "ok",
		"message":   "Self-signed certificate generated. Restart to apply.",
		"cert_info": info,
	})
}

func (s *Server) uploadCert(c *gin.Context) {
	certData, err := readFormFile(c, "cert")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cert file required"})
		return
	}
	keyData, err := readFormFile(c, "key")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "key file required"})
		return
	}

	os.MkdirAll("/app/certs", 0755)
	if err := os.WriteFile("/app/certs/server.crt", certData, 0644); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := os.WriteFile("/app/certs/server.key", keyData, 0600); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"message": "Certificate uploaded. Restart to apply.",
	})
}

func (s *Server) exportCert(c *gin.Context) {
	certFile := os.Getenv("TLS_CERT_FILE")
	if certFile == "" {
		certFile = "/app/certs/server.crt"
	}

	data, err := os.ReadFile(certFile)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "No certificate found to export"})
		return
	}

	format := c.Query("format")
	domain := c.Query("domain")
	filename := "dns-supreme-ca"
	if domain != "" {
		filename = domain
	}

	if format == "der" {
		// Convert PEM to DER
		block, _ := pem.Decode(data)
		if block == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse certificate"})
			return
		}
		c.Header("Content-Disposition", "attachment; filename="+filename+".crt")
		c.Data(http.StatusOK, "application/x-x509-ca-cert", block.Bytes)
	} else {
		c.Header("Content-Disposition", "attachment; filename="+filename+".pem")
		c.Data(http.StatusOK, "application/x-pem-file", data)
	}
}

func readFormFile(c *gin.Context, name string) ([]byte, error) {
	fh, err := c.FormFile(name)
	if err != nil {
		return nil, err
	}
	f, err := fh.Open()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

func readCertInfo(certFile string) (*certInfo, error) {
	data, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return &certInfo{
		Subject:   cert.Subject.CommonName,
		Issuer:    cert.Issuer.CommonName,
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		DNSNames:  cert.DNSNames,
		IsCA:      cert.IsCA,
		CertFile:  certFile,
	}, nil
}

// --- ACME ---

func (s *Server) getACMEConfig(c *gin.Context) {
	cfg := s.acmeClient.GetConfig()
	c.JSON(http.StatusOK, cfg)
}

func (s *Server) setACMEConfig(c *gin.Context) {
	var cfg certs.ACMEConfig
	if err := c.ShouldBindJSON(&cfg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.acmeClient.SetConfig(cfg)
	// Persist
	if data, err := json.Marshal(cfg); err == nil {
		s.db.SetSetting("acme_config", string(data))
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

type acmeRequestReq struct {
	Domain string `json:"domain"`
}

func (s *Server) loadACMEConfig() {
	if data := s.db.GetSetting("acme_config"); data != "" {
		var cfg certs.ACMEConfig
		if json.Unmarshal([]byte(data), &cfg) == nil {
			s.acmeClient.SetConfig(cfg)
		}
	}
}

func (s *Server) requestACMECert(c *gin.Context) {
	var req acmeRequestReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain required"})
		return
	}

	// Wire DNS solver to create TXT records in our zones
	s.acmeClient.SetDNSSolver(
		func(fqdn, value string) error {
			// Find or create zone for this domain
			// Add TXT record _acme-challenge
			log.Printf("[ACME] Setting DNS TXT %s = %s", fqdn, value)
			return s.db.CreateACMERecord(fqdn, value)
		},
		func(fqdn string) error {
			log.Printf("[ACME] Clearing DNS TXT %s", fqdn)
			return s.db.DeleteACMERecord(fqdn)
		},
	)

	// Run in background
	go func() {
		if err := s.acmeClient.RequestCertificate(req.Domain); err != nil {
			log.Printf("[ACME] Certificate request failed for %s: %v", req.Domain, err)
		}
	}()

	c.JSON(http.StatusOK, gin.H{"status": "requesting", "domain": req.Domain})
}
