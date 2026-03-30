package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/dachony/dns-supreme/internal/auth"
	"github.com/dachony/dns-supreme/internal/blockpage"
	"github.com/dachony/dns-supreme/internal/certs"
	"github.com/dachony/dns-supreme/internal/config"
	"github.com/dachony/dns-supreme/internal/db"
	dnsserver "github.com/dachony/dns-supreme/internal/dns"
	"github.com/dachony/dns-supreme/internal/filter"
	"github.com/dachony/dns-supreme/internal/mailer"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

type Server struct {
	cfg        config.APIConfig
	db         *db.Database
	filter     *filter.Engine
	netProtect *filter.NetProtectEngine
	blockPage  *blockpage.Server
	policies   *filter.PolicyManager
	dns        *dnsserver.Server
	dnssec     *dnsserver.DNSSECManager
	fail2ban      *Fail2Ban
	mailer        *mailer.Mailer
	acmeClient    *certs.ACMEClient
	emailMFACodes  map[int]emailMFAEntry // userID -> code+expiry
	blocklistTimer *time.Timer
	router         *gin.Engine
}

func NewServer(cfg config.APIConfig, database *db.Database, filterEngine *filter.Engine, netProtect *filter.NetProtectEngine, bp *blockpage.Server, dnsServer *dnsserver.Server) *Server {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(cors.Default())

	s := &Server{
		cfg:        cfg,
		db:         database,
		filter:     filterEngine,
		netProtect: netProtect,
		blockPage:  bp,
		policies:   filter.NewPolicyManager(),
		dns:        dnsServer,
		fail2ban:      NewFail2Ban(),
		mailer:        mailer.New(),
		acmeClient:    certs.NewACMEClient("/app/certs"),
		emailMFACodes: make(map[int]emailMFAEntry),
		dnssec:     dnsserver.NewDNSSECManager(),
		router:     router,
	}

	s.ensureDefaultAdmin()
	s.LoadMailConfig()
	s.LoadFail2BanConfig()
	s.LoadPolicies()
	s.LoadBlockPageTemplate()
	s.loadACMEConfig()
	s.getClusterFromDB()
	s.setupRoutes()
	return s
}

func (s *Server) ensureDefaultAdmin() {
	if s.db.UserCount() == 0 {
		hash, _ := auth.HashPassword("admin")
		user := &db.User{
			Username:     "admin",
			PasswordHash: hash,
			FirstName:    "Administrator",
			LastName:     "",
			Email:        "",
			Role:         "admin",
		}
		if err := s.db.CreateUser(user); err != nil {
			log.Printf("[API] Failed to create default admin: %v", err)
		} else {
			log.Printf("[API] Default admin user created (username: admin, password: admin) — CHANGE THIS!")
		}
	}
}

func (s *Server) setupRoutes() {
	// Serve frontend static files
	s.router.Static("/assets", "/app/web/dist/assets")
	s.router.NoRoute(func(c *gin.Context) {
		c.File("/app/web/dist/index.html")
	})

	api := s.router.Group("/api")

	// Health check and restart (no auth on health)
	api.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"version": "1.0.0",
		})
	})

	// Public auth endpoints
	api.POST("/auth/login", s.login)
	api.POST("/auth/mfa-verify", s.mfaVerify)

	// Protected endpoints
	protected := api.Group("")
	protected.Use(auth.AuthMiddleware())
	{
		protected.GET("/stats", s.getStats)
		protected.GET("/logs", s.getLogs)
		protected.GET("/status", s.getStatus)
		protected.GET("/system-metrics", s.getSystemMetrics)
		s.setupLogRoutes(protected)

		// Blocklists
		protected.GET("/blocklists", s.getBlocklists)
		protected.POST("/blocklists", s.addBlocklist)
		protected.POST("/blocklists/update", s.updateBlocklists)
		protected.GET("/blocklists/schedule", s.getBlocklistSchedule)
		protected.PUT("/blocklists/schedule", s.setBlocklistSchedule)
		protected.DELETE("/blocklists/:name", s.removeBlocklist)
		protected.GET("/blocklists/:name/domains", s.getBlocklistDomains)

		// Custom blocks
		protected.GET("/custom-blocks", s.getCustomBlocks)
		protected.POST("/custom-blocks", s.addCustomBlock)
		protected.DELETE("/custom-blocks/:domain", s.removeCustomBlock)

		// Allowlist
		protected.GET("/allowlist", s.getAllowlist)
		protected.POST("/allowlist", s.addAllowlist)
		protected.DELETE("/allowlist/:domain", s.removeAllowlist)

		// Categories
		protected.GET("/categories", s.getCategories)
		protected.PUT("/categories/:name", s.toggleCategory)

		// Geo-blocking
		protected.GET("/geo-blocked", s.getGeoBlocked)
		protected.PUT("/geo-blocked", s.setGeoBlocked)

		// Network protection
		// Fail2ban & access control
		protected.GET("/fail2ban", s.getFail2BanStatus)
		protected.PUT("/fail2ban/settings", s.setFail2BanSettings)
		protected.DELETE("/fail2ban/unban/:ip", s.unbanIP)
		protected.PUT("/fail2ban/allowed-ips", s.setAllowedIPs)

		// Server restart
		protected.POST("/restart", s.restartServer)

		// Mail
		protected.GET("/mail/settings", s.getMailSettings)
		protected.PUT("/mail/settings", s.setMailSettings)
		protected.POST("/mail/test", s.sendTestMail)
		protected.GET("/mail/notifications", s.getMailNotifications)
		protected.PUT("/mail/notifications", s.setMailNotifications)

		protected.GET("/network-protection", s.getNetProtectCategories)
		protected.PUT("/network-protection/:id", s.setNetProtectCategory)
		protected.GET("/network-protection/:id/entries", s.getNetProtectEntries)
		protected.GET("/network-protection/geo", s.getNetProtectGeo)
		protected.PUT("/network-protection/geo", s.setNetProtectGeo)
		protected.POST("/network-protection/refresh", s.refreshNetProtect)
		protected.GET("/network-protection/settings", s.getNetProtectSettings)
		protected.PUT("/network-protection/settings", s.setNetProtectSettings)

		// Zones
		s.setupZoneRoutes(protected)

		// Settings
		protected.GET("/settings/blockpage", s.getBlockPageTemplate)
		protected.PUT("/settings/blockpage", s.setBlockPageTemplate)
		protected.GET("/settings/forwarders", s.getForwarders)
		protected.PUT("/settings/forwarders", s.setForwarders)
		protected.GET("/settings/server", s.getServerSettings)
		protected.PUT("/settings/server", s.updateServerSettings)
		protected.GET("/settings/hostname", s.getHostname)
		protected.PUT("/settings/hostname", s.setHostname)
		protected.GET("/settings/primary-domain", s.getPrimaryDomain)
		protected.PUT("/settings/primary-domain", s.setPrimaryDomain)
		protected.GET("/settings/cluster", s.getCluster)
		protected.PUT("/settings/cluster", s.setCluster)
		protected.GET("/settings/filtering-mode", s.getFilteringMode)
		protected.PUT("/settings/filtering-mode", s.setFilteringMode)

		// Certificate management
		protected.GET("/certs", s.getCerts)
		protected.POST("/certs/generate", s.generateSelfSigned)
		protected.POST("/certs/upload", s.uploadCert)
		protected.GET("/certs/export", s.exportCert)
		protected.GET("/acme/config", s.getACMEConfig)
		protected.PUT("/acme/config", s.setACMEConfig)
		protected.POST("/acme/request", s.requestACMECert)

		// DNSSEC
		s.setupDNSSECRoutes(protected)

		// Per-device policies
		s.setupPolicyRoutes(protected)

		// Current user
		protected.GET("/auth/me", s.getMe)
		protected.PUT("/auth/password", s.changePassword)
		protected.POST("/auth/mfa/setup", s.setupMFA)
		protected.POST("/auth/mfa/enable", s.enableMFA)
		protected.DELETE("/auth/mfa", s.disableMFA)

		// User management (admin only)
		admin := protected.Group("")
		admin.Use(auth.AdminOnly())
		{
			admin.GET("/users", s.listUsers)
			admin.POST("/users", s.createUser)
			admin.PUT("/users/:id", s.updateUser)
			admin.DELETE("/users/:id", s.deleteUser)
			admin.PUT("/users/:id/password", s.resetUserPassword)
		}
	}
}

type emailMFAEntry struct {
	Code      string
	ExpiresAt time.Time
}

func (s *Server) storeEmailMFACode(userID int, code string) {
	s.emailMFACodes[userID] = emailMFAEntry{
		Code:      code,
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
}

func (s *Server) verifyEmailMFACode(userID int, code string) bool {
	entry, ok := s.emailMFACodes[userID]
	if !ok {
		return false
	}
	delete(s.emailMFACodes, userID)
	return entry.Code == code && time.Now().Before(entry.ExpiresAt)
}

func (s *Server) restartServer(c *gin.Context) {
	log.Println("[API] Server restart requested via API")
	c.JSON(http.StatusOK, gin.H{"status": "restarting"})

	// Graceful restart: signal the process to restart
	go func() {
		time.Sleep(500 * time.Millisecond)
		// Send SIGHUP to self for graceful restart
		p, err := os.FindProcess(os.Getpid())
		if err == nil {
			p.Signal(syscall.SIGHUP)
		}
	}()
}

func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.cfg.ListenAddr, s.cfg.Port)
	log.Printf("[API] Web UI and API available at http://%s", addr)

	// Restore blocklist auto-update schedule
	if v := s.db.GetSetting("blocklist_update_hours"); v != "" {
		var hours int
		if json.Unmarshal([]byte(v), &hours) == nil && hours > 0 {
			s.startBlocklistTimer(hours)
		}
	}

	go func() {
		if err := s.router.Run(addr); err != nil {
			log.Fatalf("[API] Server failed: %v", err)
		}
	}()
	return nil
}

// --- Auth Handlers ---

type loginReq struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func (s *Server) login(c *gin.Context) {
	clientIP := c.ClientIP()

	// Fail2ban: check if IP is banned
	if s.fail2ban.IsBanned(clientIP) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "Too many failed attempts. Your IP is temporarily blocked."})
		return
	}

	// Access control: check if IP is allowed
	if !s.fail2ban.IsAllowed(clientIP) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied from this IP address"})
		return
	}

	var req loginReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := s.db.GetUserByUsername(req.Username)
	if err != nil || user == nil {
		s.fail2ban.RecordFail(clientIP)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	if !auth.CheckPassword(user.PasswordHash, req.Password) {
		banned := s.fail2ban.RecordFail(clientIP)
		if banned {
			// Send security alert if admin has email
			admins, _ := s.db.GetAdminEmails()
			for _, email := range admins {
				go s.mailer.SendSecurityAlert(email,
					"IP Banned",
					fmt.Sprintf("IP %s was banned after too many failed login attempts for user '%s'", clientIP, req.Username))
			}
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	s.fail2ban.RecordSuccess(clientIP)

	// If MFA is enabled, return partial token (mfaDone=false)
	mfaDone := !user.MFAEnabled
	token, err := auth.GenerateToken(user.ID, user.Username, user.Role, mfaDone)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token generation failed"})
		return
	}

	if !mfaDone {
		// If email MFA, send the code now
		if user.MFAType == "email" && user.Email != "" && s.mailer.IsConfigured() {
			code := auth.GenerateEmailCode()
			s.storeEmailMFACode(user.ID, code)
			go s.mailer.SendMFACode(user.Email, code)
		}
		c.JSON(http.StatusOK, gin.H{
			"token":        token,
			"mfa_required": true,
			"mfa_type":     user.MFAType,
		})
		return
	}

	s.db.UpdateLastLogin(user.ID)
	c.JSON(http.StatusOK, gin.H{
		"token":        token,
		"mfa_required": false,
		"user": gin.H{
			"id":         user.ID,
			"username":   user.Username,
			"first_name": user.FirstName,
			"last_name":  user.LastName,
			"email":      user.Email,
			"role":       user.Role,
		},
	})
}

type mfaVerifyReq struct {
	Code string `json:"code" binding:"required"`
}

func (s *Server) mfaVerify(c *gin.Context) {
	header := c.GetHeader("Authorization")
	if header == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "token required"})
		return
	}
	token := header
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}

	claims, err := auth.ValidateTokenPartial(token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	var req mfaVerifyReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := s.db.GetUserByID(claims.UserID)
	if err != nil || user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
		return
	}

	// Verify based on MFA type
	verified := false
	if user.MFAType == "email" {
		verified = s.verifyEmailMFACode(user.ID, req.Code)
	} else {
		verified = auth.VerifyTOTP(user.MFASecret, req.Code)
	}
	if !verified {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid MFA code"})
		return
	}

	// Issue full token
	fullToken, _ := auth.GenerateToken(user.ID, user.Username, user.Role, true)
	s.db.UpdateLastLogin(user.ID)

	c.JSON(http.StatusOK, gin.H{
		"token": fullToken,
		"user": gin.H{
			"id":         user.ID,
			"username":   user.Username,
			"first_name": user.FirstName,
			"last_name":  user.LastName,
			"email":      user.Email,
			"role":       user.Role,
		},
	})
}

func (s *Server) getMe(c *gin.Context) {
	userID, _ := c.Get("userID")
	user, err := s.db.GetUserByID(userID.(int))
	if err != nil || user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	c.JSON(http.StatusOK, user)
}

type changePasswordReq struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required"`
}

func (s *Server) changePassword(c *gin.Context) {
	userID, _ := c.Get("userID")
	var req changePasswordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, _ := s.db.GetUserByID(userID.(int))
	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	if !auth.CheckPassword(user.PasswordHash, req.CurrentPassword) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "current password is incorrect"})
		return
	}

	hash, _ := auth.HashPassword(req.NewPassword)
	s.db.UpdateUserPassword(user.ID, hash)
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) setupMFA(c *gin.Context) {
	userID, _ := c.Get("userID")
	username, _ := c.Get("username")

	secret, err := auth.GenerateTOTPSecret()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate secret"})
		return
	}

	uri := auth.TOTPProvisioningURI(secret, username.(string), "DNS-supreme")

	// Store secret temporarily (not enabled yet)
	s.db.UpdateUserMFA(userID.(int), false, "totp", secret)

	c.JSON(http.StatusOK, gin.H{
		"secret": secret,
		"uri":    uri,
	})
}

type enableMFAReq struct {
	Code string `json:"code" binding:"required"`
}

func (s *Server) enableMFA(c *gin.Context) {
	userID, _ := c.Get("userID")
	var req enableMFAReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, _ := s.db.GetUserByID(userID.(int))
	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	if user.MFASecret == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "run MFA setup first"})
		return
	}

	if !auth.VerifyTOTP(user.MFASecret, req.Code) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid code, try again"})
		return
	}

	s.db.UpdateUserMFA(user.ID, true, "totp", user.MFASecret)
	c.JSON(http.StatusOK, gin.H{"status": "ok", "mfa_enabled": true})
}

func (s *Server) disableMFA(c *gin.Context) {
	userID, _ := c.Get("userID")
	s.db.UpdateUserMFA(userID.(int), false, "", "")
	c.JSON(http.StatusOK, gin.H{"status": "ok", "mfa_enabled": false})
}

// --- User Management (admin) ---

func (s *Server) listUsers(c *gin.Context) {
	users, err := s.db.ListUsers()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, users)
}

type createUserReq struct {
	Username  string `json:"username" binding:"required"`
	Password  string `json:"password" binding:"required"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
	Role      string `json:"role"`
}

func (s *Server) createUser(c *gin.Context) {
	var req createUserReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Role == "" {
		req.Role = "viewer"
	}
	if req.Role != "admin" && req.Role != "viewer" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role must be 'admin' or 'viewer'"})
		return
	}

	hash, _ := auth.HashPassword(req.Password)
	user := &db.User{
		Username:     req.Username,
		PasswordHash: hash,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		Email:        req.Email,
		Role:         req.Role,
	}

	if err := s.db.CreateUser(user); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "username already exists"})
		return
	}

	c.JSON(http.StatusCreated, user)
}

type updateUserReq struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
	Role      string `json:"role"`
}

func (s *Server) updateUser(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var req updateUserReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, _ := s.db.GetUserByID(id)
	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	if req.FirstName != "" {
		user.FirstName = req.FirstName
	}
	if req.LastName != "" {
		user.LastName = req.LastName
	}
	if req.Email != "" {
		user.Email = req.Email
	}
	if req.Role != "" {
		user.Role = req.Role
	}

	s.db.UpdateUser(user)
	c.JSON(http.StatusOK, user)
}

func (s *Server) deleteUser(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	currentUserID, _ := c.Get("userID")
	if id == currentUserID.(int) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot delete yourself"})
		return
	}
	if err := s.db.DeleteUser(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

type resetPasswordReq struct {
	NewPassword string `json:"new_password" binding:"required"`
}

func (s *Server) resetUserPassword(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var req resetPasswordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	hash, _ := auth.HashPassword(req.NewPassword)
	s.db.UpdateUserPassword(id, hash)
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// --- Existing Handlers ---

func (s *Server) getStats(c *gin.Context) {
	hours, _ := strconv.Atoi(c.DefaultQuery("hours", "24"))
	if hours <= 0 {
		hours = 24
	}
	stats, err := s.db.GetStats(hours)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, stats)
}

func (s *Server) getLogs(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	domain := c.Query("domain")
	clientIP := c.Query("client_ip")

	var blocked *bool
	if b := c.Query("blocked"); b != "" {
		val := b == "true"
		blocked = &val
	}

	logs, total, err := s.db.GetQueryLogs(limit, offset, domain, clientIP, blocked)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":   logs,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

func (s *Server) getBlocklists(c *gin.Context) {
	lists := s.filter.GetLists()
	totalDomains, totalLists := s.filter.Stats()
	c.JSON(http.StatusOK, gin.H{
		"lists":         lists,
		"total_domains": totalDomains,
		"total_lists":   totalLists,
	})
}

type addBlocklistReq struct {
	Name     string `json:"name" binding:"required"`
	URL      string `json:"url" binding:"required"`
	Category string `json:"category"`
}

func (s *Server) addBlocklist(c *gin.Context) {
	var req addBlocklistReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	cat := filter.Category(req.Category)
	if cat == "" {
		cat = filter.CategoryUncategorized
	}
	if err := s.filter.AddList(req.Name, req.URL, cat); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// Persist to database
	lists := s.filter.GetLists()
	for _, l := range lists {
		if l.Name == req.Name {
			s.db.SaveBlocklistWithCategory(l.Name, req.URL, string(l.Category), l.Count)
			break
		}
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) updateBlocklists(c *gin.Context) {
	lists := s.filter.GetLists()
	go func() {
		for _, l := range lists {
			if err := s.filter.UpdateList(l.Name); err != nil {
				log.Printf("[Filter] Failed to update list '%s': %v", l.Name, err)
				continue
			}
			updated := s.filter.GetLists()
			for _, u := range updated {
				if u.Name == l.Name {
					s.db.SaveBlocklistWithCategory(u.Name, l.URL, string(u.Category), u.Count)
					break
				}
			}
		}
		log.Printf("[Filter] Updated %d blocklists", len(lists))
	}()
	c.JSON(http.StatusOK, gin.H{"status": "updating", "count": len(lists)})
}

func (s *Server) getBlocklistSchedule(c *gin.Context) {
	hours := 0
	if v := s.db.GetSetting("blocklist_update_hours"); v != "" {
		json.Unmarshal([]byte(v), &hours)
	}
	c.JSON(http.StatusOK, gin.H{"interval_hours": hours})
}

func (s *Server) setBlocklistSchedule(c *gin.Context) {
	var req struct {
		IntervalHours int `json:"interval_hours"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	data, _ := json.Marshal(req.IntervalHours)
	s.db.SetSetting("blocklist_update_hours", string(data))
	s.startBlocklistTimer(req.IntervalHours)
	c.JSON(http.StatusOK, gin.H{"status": "ok", "interval_hours": req.IntervalHours})
}

func (s *Server) startBlocklistTimer(hours int) {
	if s.blocklistTimer != nil {
		s.blocklistTimer.Stop()
		s.blocklistTimer = nil
	}
	if hours <= 0 {
		log.Println("[Filter] Auto-update disabled")
		return
	}
	d := time.Duration(hours) * time.Hour
	s.blocklistTimer = time.AfterFunc(d, func() {
		log.Printf("[Filter] Auto-update triggered (every %dh)", hours)
		lists := s.filter.GetLists()
		for _, l := range lists {
			if err := s.filter.UpdateList(l.Name); err != nil {
				log.Printf("[Filter] Auto-update failed for '%s': %v", l.Name, err)
			}
		}
		s.startBlocklistTimer(hours) // re-schedule
	})
	log.Printf("[Filter] Auto-update scheduled every %d hours", hours)
}

func (s *Server) removeBlocklist(c *gin.Context) {
	name := c.Param("name")
	s.filter.RemoveList(name)
	s.db.RemoveBlocklist(name)
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) getBlocklistDomains(c *gin.Context) {
	name := c.Param("name")
	domains := s.filter.GetListDomains(name, 200)
	c.JSON(http.StatusOK, gin.H{"name": name, "domains": domains, "sample_size": len(domains)})
}

func (s *Server) getCustomBlocks(c *gin.Context) {
	blocks := s.filter.GetCustomBlocks()
	c.JSON(http.StatusOK, blocks)
}

type customBlockReq struct {
	Domain string `json:"domain" binding:"required"`
	Reason string `json:"reason"`
}

func (s *Server) addCustomBlock(c *gin.Context) {
	var req customBlockReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.filter.AddCustomBlock(req.Domain, req.Reason)
	s.persistCustomBlocks()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) removeCustomBlock(c *gin.Context) {
	domain := c.Param("domain")
	s.filter.RemoveCustomBlock(domain)
	s.persistCustomBlocks()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) persistCustomBlocks() {
	blocks := s.filter.GetCustomBlocks()
	if data, err := json.Marshal(blocks); err == nil {
		s.db.SetSetting("custom_blocks", string(data))
	}
}

func (s *Server) getAllowlist(c *gin.Context) {
	list := s.filter.GetAllowlist()
	c.JSON(http.StatusOK, list)
}

type allowlistReq struct {
	Domain string `json:"domain" binding:"required"`
}

func (s *Server) addAllowlist(c *gin.Context) {
	var req allowlistReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.filter.AddAllowlistDomain(req.Domain)
	s.persistAllowlist()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) removeAllowlist(c *gin.Context) {
	domain := c.Param("domain")
	s.filter.RemoveAllowlistDomain(domain)
	s.persistAllowlist()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) persistAllowlist() {
	list := s.filter.GetAllowlist()
	if data, err := json.Marshal(list); err == nil {
		s.db.SetSetting("allowlist", string(data))
	}
}

func (s *Server) getStatus(c *gin.Context) {
	totalDomains, totalLists := s.filter.Stats()
	npCats := 0
	if s.netProtect != nil {
		for _, cat := range s.netProtect.GetCategories() {
			if cat.Enabled {
				npCats++
			}
		}
	}
	geoCodes := 0
	if s.netProtect != nil {
		geoCodes = len(s.netProtect.GetGeoBlocked())
	}
	bannedIPs := 0
	if s.fail2ban != nil {
		bannedIPs = len(s.fail2ban.GetBannedIPs())
	}
	c.JSON(http.StatusOK, gin.H{
		"status":                "running",
		"version":               "1.0.0",
		"total_domains":         totalDomains,
		"total_lists":           totalLists,
		"np_active_feeds":       npCats,
		"geo_blocked_countries": geoCodes,
		"banned_ips":            bannedIPs,
		"users":                 s.db.UserCount(),
		"smtp_configured":       s.mailer.IsConfigured(),
	})
}

// --- Categories ---

func (s *Server) getCategories(c *gin.Context) {
	categories := s.filter.GetCategories()
	catStats := s.filter.CategoryStats()
	result := make([]gin.H, 0)
	for cat, enabled := range categories {
		result = append(result, gin.H{
			"name":    string(cat),
			"enabled": enabled,
			"domains": catStats[cat],
		})
	}
	c.JSON(http.StatusOK, result)
}

type toggleCategoryReq struct {
	Enabled bool `json:"enabled"`
}

func (s *Server) toggleCategory(c *gin.Context) {
	name := c.Param("name")
	var req toggleCategoryReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	cat := filter.Category(name)
	if req.Enabled {
		s.filter.EnableCategory(cat)
	} else {
		s.filter.DisableCategory(cat)
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// --- Geo-blocking ---

func (s *Server) getGeoBlocked(c *gin.Context) {
	countries := s.filter.GetGeoBlocked()
	c.JSON(http.StatusOK, countries)
}

type setGeoBlockedReq struct {
	Countries []string `json:"countries"`
}

func (s *Server) setGeoBlocked(c *gin.Context) {
	var req setGeoBlockedReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.filter.SetGeoBlocked(req.Countries)
	c.JSON(http.StatusOK, gin.H{"status": "ok", "blocked_countries": len(req.Countries)})
}
