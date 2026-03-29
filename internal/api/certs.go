package api

import (
	"crypto/x509"
	"encoding/pem"
	"io"
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
