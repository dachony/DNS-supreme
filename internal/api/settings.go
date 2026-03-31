package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// Block page visual settings stored as JSON
type blockPageSettings struct {
	Logo        string `json:"logo"`
	Heading     string `json:"heading"`
	Message     string `json:"message"`
	Description string `json:"description"`
	Footer      string `json:"footer"`
	Color       string `json:"color"`
}

type blockPageReq struct {
	HTML     string             `json:"html"`
	Settings *blockPageSettings `json:"settings,omitempty"`
}

func (s *Server) getBlockPageTemplate(c *gin.Context) {
	html := ""
	if s.blockPage != nil {
		html = s.blockPage.GetCustomTemplate()
	}
	// Try DB if in-memory is empty
	if html == "" {
		html = s.db.GetSetting("block_page_html")
	}

	// Load visual settings
	var settings blockPageSettings
	if data := s.db.GetSetting("block_page_visual"); data != "" {
		json.Unmarshal([]byte(data), &settings)
	}

	c.JSON(http.StatusOK, gin.H{
		"html":     html,
		"settings": settings,
	})
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

	html := req.HTML
	if html == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "html is required"})
		return
	}

	if err := s.blockPage.SetCustomTemplate(html); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.db.SetSetting("block_page_html", html)

	// Save visual settings if provided
	if req.Settings != nil {
		if data, err := json.Marshal(req.Settings); err == nil {
			s.db.SetSetting("block_page_visual", string(data))
		}
	}

	// Audit
	userID, _ := c.Get("userID")
	username, _ := c.Get("username")
	s.db.LogAudit(userID.(int), username.(string), "settings_change", "Block page template updated", c.ClientIP())

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) uploadBlockPageLogo(c *gin.Context) {
	file, header, err := c.Request.FormFile("logo")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no file uploaded"})
		return
	}
	defer file.Close()

	// Sanitize extension to prevent path traversal
	ext := filepath.Ext(filepath.Base(header.Filename))
	ext = strings.ToLower(ext)
	allowed := map[string]bool{".png": true, ".jpg": true, ".jpeg": true, ".svg": true, ".gif": true, ".webp": true, ".ico": true}
	if !allowed[ext] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid file type, allowed: png, jpg, svg, gif, webp, ico"})
		return
	}

	// Limit to 2MB
	if header.Size > 2*1024*1024 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file too large, max 2MB"})
		return
	}

	// Ensure upload dir exists
	uploadDir := "/app/data/uploads"
	os.MkdirAll(uploadDir, 0755)

	// Save with timestamp to avoid caching issues
	filename := "logo_" + strings.ReplaceAll(time.Now().Format("20060102_150405"), " ", "") + ext
	destPath := filepath.Join(uploadDir, filename)

	dest, err := os.Create(destPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save file"})
		return
	}
	defer dest.Close()
	io.Copy(dest, file)

	// Clean up old logos
	entries, _ := os.ReadDir(uploadDir)
	for _, e := range entries {
		if e.Name() != filename && strings.HasPrefix(e.Name(), "logo_") {
			os.Remove(filepath.Join(uploadDir, e.Name()))
		}
	}

	logoURL := "/uploads/" + filename
	s.db.SetSetting("block_page_logo", logoURL)

	slog.Info("block page logo uploaded", "component", "api", "file", filename, "size", header.Size)

	c.JSON(http.StatusOK, gin.H{"url": logoURL})
}

func (s *Server) LoadBlockPageTemplate() {
	if html := s.db.GetSetting("block_page_html"); html != "" && s.blockPage != nil {
		s.blockPage.SetCustomTemplate(html)
	}
	// Load block page domain
	if domain := s.db.GetSetting("block_page_domain"); domain != "" {
		s.dns.SetBlockPageDomain(domain)
	}
}

func (s *Server) getBlockPageDomain(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"domain": s.dns.GetBlockPageDomain()})
}

type blockPageDomainReq struct {
	Domain string `json:"domain"`
}

func (s *Server) setBlockPageDomain(c *gin.Context) {
	var req blockPageDomainReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.dns.SetBlockPageDomain(req.Domain)
	s.db.SetSetting("block_page_domain", req.Domain)

	userID, _ := c.Get("userID")
	username, _ := c.Get("username")
	s.db.LogAudit(userID.(int), username.(string), "settings_change", "Block page domain set to: "+req.Domain, c.ClientIP())

	c.JSON(http.StatusOK, gin.H{"status": "ok", "domain": req.Domain})
}
