package db

import (
	"fmt"
	"strings"
	"time"
)

type Zone struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"` // primary, secondary
	SOASerial uint32    `json:"soa_serial"`
	TTL       int       `json:"ttl"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type DNSRecord struct {
	ID       int       `json:"id"`
	ZoneID   int       `json:"zone_id"`
	Name     string    `json:"name"`
	Type     string    `json:"type"` // A, AAAA, CNAME, MX, TXT, NS, SRV, PTR, CAA
	Value    string    `json:"value"`
	TTL      int       `json:"ttl"`
	Priority int       `json:"priority,omitempty"` // for MX, SRV
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (d *Database) migrateZones() error {
	schema := `
	CREATE TABLE IF NOT EXISTS zones (
		id SERIAL PRIMARY KEY,
		name VARCHAR(255) NOT NULL UNIQUE,
		type VARCHAR(20) NOT NULL DEFAULT 'primary',
		soa_serial INTEGER NOT NULL DEFAULT 1,
		ttl INTEGER NOT NULL DEFAULT 3600,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS dns_records (
		id SERIAL PRIMARY KEY,
		zone_id INTEGER NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
		name VARCHAR(255) NOT NULL,
		type VARCHAR(10) NOT NULL,
		value TEXT NOT NULL,
		ttl INTEGER NOT NULL DEFAULT 3600,
		priority INTEGER NOT NULL DEFAULT 0,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE INDEX IF NOT EXISTS idx_dns_records_zone ON dns_records (zone_id);
	CREATE INDEX IF NOT EXISTS idx_dns_records_name_type ON dns_records (name, type);
	`
	_, err := d.db.Exec(schema)
	return err
}

// --- Zones CRUD ---

func (d *Database) CreateZone(z *Zone) error {
	return d.db.QueryRow(`
		INSERT INTO zones (name, type, ttl) VALUES ($1, $2, $3)
		RETURNING id, soa_serial, created_at, updated_at
	`, z.Name, z.Type, z.TTL).Scan(&z.ID, &z.SOASerial, &z.CreatedAt, &z.UpdatedAt)
}

func (d *Database) ListZones() ([]Zone, error) {
	rows, err := d.db.Query(`SELECT id, name, type, soa_serial, ttl, created_at, updated_at FROM zones ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	zones := make([]Zone, 0)
	for rows.Next() {
		var z Zone
		rows.Scan(&z.ID, &z.Name, &z.Type, &z.SOASerial, &z.TTL, &z.CreatedAt, &z.UpdatedAt)
		zones = append(zones, z)
	}
	return zones, nil
}

func (d *Database) GetZone(id int) (*Zone, error) {
	z := &Zone{}
	err := d.db.QueryRow(`SELECT id, name, type, soa_serial, ttl, created_at, updated_at FROM zones WHERE id=$1`, id).
		Scan(&z.ID, &z.Name, &z.Type, &z.SOASerial, &z.TTL, &z.CreatedAt, &z.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return z, nil
}

func (d *Database) GetZoneByName(name string) (*Zone, error) {
	z := &Zone{}
	err := d.db.QueryRow(`SELECT id, name, type, soa_serial, ttl, created_at, updated_at FROM zones WHERE name=$1`, name).
		Scan(&z.ID, &z.Name, &z.Type, &z.SOASerial, &z.TTL, &z.CreatedAt, &z.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return z, nil
}

func (d *Database) DeleteZone(id int) error {
	result, err := d.db.Exec(`DELETE FROM zones WHERE id=$1`, id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("zone not found")
	}
	return nil
}

func (d *Database) IncrementSOA(zoneID int) error {
	_, err := d.db.Exec(`UPDATE zones SET soa_serial = soa_serial + 1, updated_at = NOW() WHERE id=$1`, zoneID)
	return err
}

// --- Records CRUD ---

func (d *Database) CreateRecord(r *DNSRecord) error {
	err := d.db.QueryRow(`
		INSERT INTO dns_records (zone_id, name, type, value, ttl, priority)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at, updated_at
	`, r.ZoneID, r.Name, r.Type, r.Value, r.TTL, r.Priority).
		Scan(&r.ID, &r.CreatedAt, &r.UpdatedAt)
	if err == nil {
		d.IncrementSOA(r.ZoneID)
	}
	return err
}

func (d *Database) ListRecords(zoneID int) ([]DNSRecord, error) {
	rows, err := d.db.Query(`
		SELECT id, zone_id, name, type, value, ttl, priority, created_at, updated_at
		FROM dns_records WHERE zone_id=$1 ORDER BY name, type
	`, zoneID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := make([]DNSRecord, 0)
	for rows.Next() {
		var r DNSRecord
		rows.Scan(&r.ID, &r.ZoneID, &r.Name, &r.Type, &r.Value, &r.TTL, &r.Priority, &r.CreatedAt, &r.UpdatedAt)
		records = append(records, r)
	}
	return records, nil
}

func (d *Database) UpdateRecord(r *DNSRecord) error {
	_, err := d.db.Exec(`
		UPDATE dns_records SET name=$1, type=$2, value=$3, ttl=$4, priority=$5, updated_at=NOW()
		WHERE id=$6
	`, r.Name, r.Type, r.Value, r.TTL, r.Priority, r.ID)
	if err == nil {
		d.IncrementSOA(r.ZoneID)
	}
	return err
}

func (d *Database) DeleteRecord(id, zoneID int) error {
	result, err := d.db.Exec(`DELETE FROM dns_records WHERE id=$1`, id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("record not found")
	}
	d.IncrementSOA(zoneID)
	return nil
}

// FindRecords looks up records matching a fully-qualified name and type.
// It splits "www.example.com" into record name "www" and zone "example.com",
// trying all possible splits.
func (d *Database) FindRecords(name, rtype string) ([]DNSRecord, error) {
	parts := strings.Split(name, ".")

	// Try each possible split: www.example.com -> record="www", zone="example.com"
	// Also try: record="@", zone="example.com" for apex queries
	for i := 1; i < len(parts); i++ {
		recName := strings.Join(parts[:i], ".")
		zoneName := strings.Join(parts[i:], ".")

		records, err := d.findRecordsInZone(zoneName, recName, rtype)
		if err == nil && len(records) > 0 {
			return records, nil
		}
	}

	// Try apex match: name = "@", zone = full name
	records, err := d.findRecordsInZone(name, "@", rtype)
	if err == nil && len(records) > 0 {
		return records, nil
	}

	return nil, nil
}

func (d *Database) findRecordsInZone(zoneName, recName, rtype string) ([]DNSRecord, error) {
	rows, err := d.db.Query(`
		SELECT r.id, r.zone_id, r.name, r.type, r.value, r.ttl, r.priority, r.created_at, r.updated_at
		FROM dns_records r
		JOIN zones z ON r.zone_id = z.id
		WHERE z.name = $1 AND r.name = $2 AND r.type = $3
	`, zoneName, recName, rtype)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := make([]DNSRecord, 0)
	for rows.Next() {
		var r DNSRecord
		rows.Scan(&r.ID, &r.ZoneID, &r.Name, &r.Type, &r.Value, &r.TTL, &r.Priority, &r.CreatedAt, &r.UpdatedAt)
		records = append(records, r)
	}
	return records, nil
}
