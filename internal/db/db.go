package db

import (
	"database/sql"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/dachony/dns-supreme/internal/config"
	_ "github.com/lib/pq"
)

type QueryLog struct {
	ID             int64     `json:"id"`
	Timestamp      time.Time `json:"timestamp"`
	ClientIP       string    `json:"client_ip"`
	ClientHostname string    `json:"client_hostname,omitempty"`
	Domain         string    `json:"domain"`
	QueryType      string    `json:"query_type"`
	Blocked        bool      `json:"blocked"`
	BlockRule      string    `json:"block_rule,omitempty"`
	ResponseIP     string    `json:"response_ip,omitempty"`
	LatencyMs      float64   `json:"latency_ms"`
	Upstream       string    `json:"upstream,omitempty"`
	Protocol       string    `json:"protocol,omitempty"`
}

type Stats struct {
	TotalQueries   int64            `json:"total_queries"`
	BlockedQueries int64            `json:"blocked_queries"`
	AllowedQueries int64            `json:"allowed_queries"`
	BlockedPercent float64          `json:"blocked_percent"`
	TopDomains     []DomainCount    `json:"top_domains"`
	TopBlocked     []DomainCount    `json:"top_blocked"`
	TopClients     []ClientCount    `json:"top_clients"`
	QueryTypes     []QueryTypeCount `json:"query_types"`
	QueriesOverTime []TimeCount     `json:"queries_over_time"`
}

type DomainCount struct {
	Domain string `json:"domain"`
	Count  int64  `json:"count"`
}

type ClientCount struct {
	ClientIP string `json:"client_ip"`
	Count    int64  `json:"count"`
}

type QueryTypeCount struct {
	Type  string `json:"type"`
	Count int64  `json:"count"`
}

type TimeCount struct {
	Time    time.Time `json:"time"`
	Total   int64     `json:"total"`
	Blocked int64     `json:"blocked"`
}

type Database struct {
	db        *sql.DB
	cfg       config.LoggingConfig
	buffer    []QueryLog
	mu        sync.Mutex
	flushChan chan struct{}
}

func New(dbCfg config.DatabaseConfig, logCfg config.LoggingConfig) (*Database, error) {
	db, err := sql.Open("postgres", dbCfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Wait for DB to be ready
	for i := 0; i < 30; i++ {
		if err := db.Ping(); err == nil {
			break
		}
		log.Printf("[DB] Waiting for database... (%d/30)", i+1)
		time.Sleep(1 * time.Second)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("database not ready: %w", err)
	}

	d := &Database{
		db:        db,
		cfg:       logCfg,
		buffer:    make([]QueryLog, 0, logCfg.BatchSize),
		flushChan: make(chan struct{}, 1),
	}

	if err := d.migrate(); err != nil {
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	go d.flushLoop()
	d.startRetentionCleanup()

	log.Printf("[DB] Connected to PostgreSQL")
	return d, nil
}

func (d *Database) startRetentionCleanup() {
	// Run immediately on startup, then every hour
	d.cleanOldLogs()
	ticker := time.NewTicker(1 * time.Hour)
	go func() {
		for range ticker.C {
			d.cleanOldLogs()
		}
	}()
}

func (d *Database) cleanOldLogs() {
	if d.cfg.RetentionDays <= 0 {
		return
	}
	cutoff := time.Now().AddDate(0, 0, -d.cfg.RetentionDays)
	result, err := d.db.Exec("DELETE FROM query_log WHERE timestamp < $1", cutoff)
	if err != nil {
		log.Printf("[DB] Retention cleanup error: %v", err)
		return
	}
	if rows, _ := result.RowsAffected(); rows > 0 {
		log.Printf("[DB] Retention cleanup: deleted %d logs older than %d days", rows, d.cfg.RetentionDays)
	}
}

func (d *Database) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS query_log (
		id BIGSERIAL PRIMARY KEY,
		timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		client_ip VARCHAR(45) NOT NULL,
		domain VARCHAR(255) NOT NULL,
		query_type VARCHAR(10) NOT NULL,
		blocked BOOLEAN NOT NULL DEFAULT FALSE,
		block_rule VARCHAR(255),
		response_ip VARCHAR(45),
		latency_ms DOUBLE PRECISION,
		upstream VARCHAR(100),
		protocol VARCHAR(10) DEFAULT ''
	);

	CREATE INDEX IF NOT EXISTS idx_query_log_timestamp ON query_log (timestamp DESC);
	CREATE INDEX IF NOT EXISTS idx_query_log_domain ON query_log (domain);
	CREATE INDEX IF NOT EXISTS idx_query_log_client_ip ON query_log (client_ip);
	CREATE INDEX IF NOT EXISTS idx_query_log_blocked ON query_log (blocked);

	CREATE TABLE IF NOT EXISTS blocklists (
		id SERIAL PRIMARY KEY,
		name VARCHAR(100) NOT NULL UNIQUE,
		url TEXT NOT NULL,
		enabled BOOLEAN NOT NULL DEFAULT TRUE,
		domain_count INTEGER NOT NULL DEFAULT 0,
		last_updated TIMESTAMPTZ,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		username VARCHAR(50) NOT NULL UNIQUE,
		password_hash VARCHAR(255) NOT NULL,
		first_name VARCHAR(100) NOT NULL DEFAULT '',
		last_name VARCHAR(100) NOT NULL DEFAULT '',
		email VARCHAR(255) NOT NULL DEFAULT '',
		role VARCHAR(20) NOT NULL DEFAULT 'viewer',
		mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
		mfa_type VARCHAR(10) NOT NULL DEFAULT '',
		mfa_secret VARCHAR(255) NOT NULL DEFAULT '',
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		last_login TIMESTAMPTZ
	);

	CREATE TABLE IF NOT EXISTS settings (
		key VARCHAR(100) PRIMARY KEY,
		value TEXT NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS audit_log (
		id BIGSERIAL PRIMARY KEY,
		timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		user_id INTEGER,
		username VARCHAR(50),
		action VARCHAR(50) NOT NULL,
		detail TEXT,
		client_ip VARCHAR(45)
	);
	CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log (timestamp DESC);
	`
	_, err := d.db.Exec(schema)
	if err != nil {
		return err
	}
	// Add columns if missing (for upgrades)
	d.db.Exec("ALTER TABLE query_log ADD COLUMN IF NOT EXISTS protocol VARCHAR(10) DEFAULT ''")
	d.db.Exec("ALTER TABLE query_log ADD COLUMN IF NOT EXISTS client_hostname VARCHAR(255) DEFAULT ''")
	return d.migrateZones()
}

func (d *Database) LogQuery(entry QueryLog) {
	d.mu.Lock()
	d.buffer = append(d.buffer, entry)
	shouldFlush := len(d.buffer) >= d.cfg.BatchSize
	d.mu.Unlock()

	if shouldFlush {
		select {
		case d.flushChan <- struct{}{}:
		default:
		}
	}
}

func (d *Database) flushLoop() {
	ticker := time.NewTicker(time.Duration(d.cfg.FlushIntervalS) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			d.flush()
		case <-d.flushChan:
			d.flush()
		}
	}
}

func (d *Database) flush() {
	d.mu.Lock()
	if len(d.buffer) == 0 {
		d.mu.Unlock()
		return
	}
	entries := d.buffer
	d.buffer = make([]QueryLog, 0, d.cfg.BatchSize)
	d.mu.Unlock()

	tx, err := d.db.Begin()
	if err != nil {
		log.Printf("[DB] Failed to begin transaction: %v", err)
		return
	}

	stmt, err := tx.Prepare(`
		INSERT INTO query_log (timestamp, client_ip, client_hostname, domain, query_type, blocked, block_rule, response_ip, latency_ms, upstream, protocol)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`)
	if err != nil {
		tx.Rollback()
		log.Printf("[DB] Failed to prepare statement: %v", err)
		return
	}
	defer stmt.Close()

	for _, e := range entries {
		_, err := stmt.Exec(e.Timestamp, e.ClientIP, e.ClientHostname, e.Domain, e.QueryType, e.Blocked, e.BlockRule, e.ResponseIP, e.LatencyMs, e.Upstream, e.Protocol)
		if err != nil {
			log.Printf("[DB] Failed to insert query log: %v", err)
		}
	}

	if err := tx.Commit(); err != nil {
		log.Printf("[DB] Failed to commit: %v", err)
	}
}

func (d *Database) GetQueryLogs(limit, offset int, domain, clientIP string, blocked *bool) ([]QueryLog, int64, error) {
	where := "WHERE 1=1"
	args := make([]interface{}, 0)
	argN := 1

	if domain != "" {
		where += fmt.Sprintf(" AND domain ILIKE $%d", argN)
		args = append(args, "%"+domain+"%")
		argN++
	}
	if clientIP != "" {
		where += fmt.Sprintf(" AND client_ip LIKE $%d", argN)
		args = append(args, clientIP+"%")
		argN++
	}
	if blocked != nil {
		where += fmt.Sprintf(" AND blocked = $%d", argN)
		args = append(args, *blocked)
		argN++
	}

	// Count
	var total int64
	countQuery := "SELECT COUNT(*) FROM query_log " + where
	d.db.QueryRow(countQuery, args...).Scan(&total)

	// Fetch
	query := fmt.Sprintf("SELECT id, timestamp, client_ip, COALESCE(client_hostname,''), domain, query_type, blocked, COALESCE(block_rule,''), COALESCE(response_ip,''), COALESCE(latency_ms,0), COALESCE(upstream,''), COALESCE(protocol,'') FROM query_log %s ORDER BY timestamp DESC LIMIT $%d OFFSET $%d", where, argN, argN+1)
	args = append(args, limit, offset)

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	logs := make([]QueryLog, 0)
	for rows.Next() {
		var l QueryLog
		err := rows.Scan(&l.ID, &l.Timestamp, &l.ClientIP, &l.ClientHostname, &l.Domain, &l.QueryType, &l.Blocked, &l.BlockRule, &l.ResponseIP, &l.LatencyMs, &l.Upstream, &l.Protocol)
		if err != nil {
			continue
		}
		logs = append(logs, l)
	}

	return logs, total, nil
}

func (d *Database) GetStats(hours int) (*Stats, error) {
	since := time.Now().Add(-time.Duration(hours) * time.Hour)
	stats := &Stats{}

	// Total and blocked counts
	d.db.QueryRow("SELECT COUNT(*) FROM query_log WHERE timestamp > $1", since).Scan(&stats.TotalQueries)
	d.db.QueryRow("SELECT COUNT(*) FROM query_log WHERE timestamp > $1 AND blocked = true", since).Scan(&stats.BlockedQueries)
	stats.AllowedQueries = stats.TotalQueries - stats.BlockedQueries
	if stats.TotalQueries > 0 {
		stats.BlockedPercent = float64(stats.BlockedQueries) / float64(stats.TotalQueries) * 100
	}

	// Top domains
	stats.TopDomains = d.topDomains(since, false, 10)
	stats.TopBlocked = d.topDomains(since, true, 10)

	// Top clients
	rows, err := d.db.Query("SELECT client_ip, COUNT(*) as cnt FROM query_log WHERE timestamp > $1 GROUP BY client_ip ORDER BY cnt DESC LIMIT 10", since)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var c ClientCount
			rows.Scan(&c.ClientIP, &c.Count)
			stats.TopClients = append(stats.TopClients, c)
		}
	}

	// Query types
	rows2, err := d.db.Query("SELECT query_type, COUNT(*) as cnt FROM query_log WHERE timestamp > $1 GROUP BY query_type ORDER BY cnt DESC", since)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var qt QueryTypeCount
			rows2.Scan(&qt.Type, &qt.Count)
			stats.QueryTypes = append(stats.QueryTypes, qt)
		}
	}

	// Queries over time (hourly buckets)
	rows3, err := d.db.Query(`
		SELECT date_trunc('hour', timestamp) as hour,
			COUNT(*) as total,
			COUNT(*) FILTER (WHERE blocked = true) as blocked
		FROM query_log
		WHERE timestamp > $1
		GROUP BY hour
		ORDER BY hour
	`, since)
	if err == nil {
		defer rows3.Close()
		for rows3.Next() {
			var tc TimeCount
			rows3.Scan(&tc.Time, &tc.Total, &tc.Blocked)
			stats.QueriesOverTime = append(stats.QueriesOverTime, tc)
		}
	}

	return stats, nil
}

func (d *Database) topDomains(since time.Time, blocked bool, limit int) []DomainCount {
	query := "SELECT domain, COUNT(*) as cnt FROM query_log WHERE timestamp > $1 AND blocked = $2 GROUP BY domain ORDER BY cnt DESC LIMIT $3"
	rows, err := d.db.Query(query, since, blocked, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()

	result := make([]DomainCount, 0)
	for rows.Next() {
		var dc DomainCount
		rows.Scan(&dc.Domain, &dc.Count)
		result = append(result, dc)
	}
	return result
}

func (d *Database) QueryRow(query string, args ...interface{}) *sql.Row {
	return d.db.QueryRow(query, args...)
}

func (d *Database) Exec(query string, args ...interface{}) (sql.Result, error) {
	return d.db.Exec(query, args...)
}

func (d *Database) Query(query string, args ...interface{}) (*sql.Rows, error) {
	return d.db.Query(query, args...)
}

func (d *Database) Close() {
	d.flush()
	d.db.Close()
}
