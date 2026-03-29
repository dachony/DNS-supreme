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
	// Try DB if in-memory is empty
	if html == "" {
		html = s.db.GetSetting("block_page_html")
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
	s.db.SetSetting("block_page_html", req.HTML)
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) LoadBlockPageTemplate() {
	if html := s.db.GetSetting("block_page_html"); html != "" && s.blockPage != nil {
		s.blockPage.SetCustomTemplate(html)
	}
}
