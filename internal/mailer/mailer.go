package mailer

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/smtp"
	"strings"
	"sync"
)

type Config struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	From       string `json:"from"`
	FromName   string `json:"from_name"`
	Encryption string `json:"encryption"` // "starttls", "ssl", "none"
}

type NotifConfig struct {
	SecurityAlerts bool `json:"security_alerts"`
	DailyReport    bool `json:"daily_report"`
	WeeklyReport   bool `json:"weekly_report"`
	CertExpiry     bool `json:"cert_expiry"`
	FeedErrors     bool `json:"feed_errors"`
	HighBlockRate  bool `json:"high_block_rate"`
}

type Mailer struct {
	cfg   Config
	notif NotifConfig
	mu    sync.RWMutex
}

func New() *Mailer {
	return &Mailer{
		cfg: Config{
			Port:       587,
			FromName:   "DNS Supreme",
			Encryption: "starttls",
		},
		notif: NotifConfig{
			SecurityAlerts: true,
			CertExpiry:     true,
			FeedErrors:     true,
		},
	}
}

func (m *Mailer) GetConfig() Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg
}

func (m *Mailer) SetConfig(cfg Config) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg = cfg
}

func (m *Mailer) GetNotifConfig() NotifConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.notif
}

func (m *Mailer) SetNotifConfig(n NotifConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.notif = n
}

func (m *Mailer) IsConfigured() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg.Host != "" && m.cfg.From != ""
}

// Send sends an email. Returns error if SMTP is not configured or sending fails.
func (m *Mailer) Send(to, subject, body string) error {
	m.mu.RLock()
	cfg := m.cfg
	m.mu.RUnlock()

	if cfg.Host == "" || cfg.From == "" {
		return fmt.Errorf("SMTP not configured")
	}

	from := cfg.From
	if cfg.FromName != "" {
		from = fmt.Sprintf("%s <%s>", cfg.FromName, cfg.From)
	}

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		from, to, subject, body)

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)

	var auth smtp.Auth
	if cfg.Username != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	}

	switch cfg.Encryption {
	case "ssl":
		return m.sendSSL(addr, auth, cfg.From, to, []byte(msg))
	case "starttls":
		return m.sendSTARTTLS(addr, auth, cfg.From, to, []byte(msg))
	default:
		return smtp.SendMail(addr, auth, cfg.From, []string{to}, []byte(msg))
	}
}

func (m *Mailer) sendSTARTTLS(addr string, auth smtp.Auth, from, to string, msg []byte) error {
	c, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer c.Close()

	host := strings.Split(addr, ":")[0]
	tlsConfig := &tls.Config{ServerName: host}
	if err := c.StartTLS(tlsConfig); err != nil {
		return fmt.Errorf("starttls: %w", err)
	}
	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	w.Write(msg)
	w.Close()
	return c.Quit()
}

func (m *Mailer) sendSSL(addr string, auth smtp.Auth, from, to string, msg []byte) error {
	host := strings.Split(addr, ":")[0]
	tlsConfig := &tls.Config{ServerName: host}
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("tls dial: %w", err)
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	defer c.Close()

	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	w.Write(msg)
	w.Close()
	return c.Quit()
}

// SendTest sends a test email to verify SMTP configuration
func (m *Mailer) SendTest(to string) error {
	body := `<h2>DNS Supreme — Test Email</h2>
<p>This is a test email from your DNS Supreme server.</p>
<p>If you received this, your SMTP configuration is working correctly.</p>
<p style="color:#64748b;font-size:12px">Sent from DNS Supreme</p>`
	return m.Send(to, "DNS Supreme — SMTP Test", body)
}

// SendMFACode sends a one-time MFA code via email
func (m *Mailer) SendMFACode(to, code string) error {
	body := fmt.Sprintf(`<h2>DNS Supreme — Login Verification</h2>
<p>Your one-time verification code is:</p>
<div style="font-size:32px;font-weight:bold;letter-spacing:6px;color:#0ea5e9;padding:16px 0">%s</div>
<p>This code expires in 5 minutes. If you didn't request this, ignore this email.</p>
<p style="color:#64748b;font-size:12px">Sent from DNS Supreme</p>`, code)
	return m.Send(to, "DNS Supreme — Verification Code", body)
}

// SendSecurityAlert sends a security notification
func (m *Mailer) SendSecurityAlert(to, event, details string) error {
	if !m.notif.SecurityAlerts {
		return nil
	}
	body := fmt.Sprintf(`<h2>DNS Supreme — Security Alert</h2>
<p><strong>Event:</strong> %s</p>
<p><strong>Details:</strong> %s</p>
<p style="color:#64748b;font-size:12px">Sent from DNS Supreme</p>`, event, details)
	err := m.Send(to, "DNS Supreme — Security Alert: "+event, body)
	if err != nil {
		slog.Error("failed to send security alert", "component", "mailer", "error", err)
	}
	return err
}
