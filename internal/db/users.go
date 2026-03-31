package db

import (
	"database/sql"
	"fmt"
	"time"
)

type User struct {
	ID           int       `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	FirstName    string    `json:"first_name"`
	LastName     string    `json:"last_name"`
	Email        string    `json:"email"`
	Role         string    `json:"role"`
	MFAEnabled   bool      `json:"mfa_enabled"`
	MFAType      string    `json:"mfa_type,omitempty"`
	MFASecret    string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	LastLogin    *time.Time `json:"last_login,omitempty"`
}

func (d *Database) CreateUser(u *User) error {
	err := d.db.QueryRow(`
		INSERT INTO users (username, password_hash, first_name, last_name, email, role, mfa_enabled, mfa_type, mfa_secret)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, created_at, updated_at
	`, u.Username, u.PasswordHash, u.FirstName, u.LastName, u.Email, u.Role, u.MFAEnabled, u.MFAType, u.MFASecret).
		Scan(&u.ID, &u.CreatedAt, &u.UpdatedAt)
	return err
}

func (d *Database) GetUserByUsername(username string) (*User, error) {
	u := &User{}
	err := d.db.QueryRow(`
		SELECT id, username, password_hash, first_name, last_name, email, role,
			mfa_enabled, mfa_type, mfa_secret, created_at, updated_at, last_login
		FROM users WHERE username = $1
	`, username).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.FirstName, &u.LastName,
		&u.Email, &u.Role, &u.MFAEnabled, &u.MFAType, &u.MFASecret,
		&u.CreatedAt, &u.UpdatedAt, &u.LastLogin)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return u, err
}

func (d *Database) GetUserByID(id int) (*User, error) {
	u := &User{}
	err := d.db.QueryRow(`
		SELECT id, username, password_hash, first_name, last_name, email, role,
			mfa_enabled, mfa_type, mfa_secret, created_at, updated_at, last_login
		FROM users WHERE id = $1
	`, id).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.FirstName, &u.LastName,
		&u.Email, &u.Role, &u.MFAEnabled, &u.MFAType, &u.MFASecret,
		&u.CreatedAt, &u.UpdatedAt, &u.LastLogin)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return u, err
}

func (d *Database) ListUsers() ([]User, error) {
	rows, err := d.db.Query(`
		SELECT id, username, first_name, last_name, email, role,
			mfa_enabled, mfa_type, created_at, updated_at, last_login
		FROM users ORDER BY id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := make([]User, 0)
	for rows.Next() {
		var u User
		err := rows.Scan(&u.ID, &u.Username, &u.FirstName, &u.LastName, &u.Email,
			&u.Role, &u.MFAEnabled, &u.MFAType, &u.CreatedAt, &u.UpdatedAt, &u.LastLogin)
		if err != nil {
			continue
		}
		users = append(users, u)
	}
	return users, nil
}

func (d *Database) UpdateUser(u *User) error {
	_, err := d.db.Exec(`
		UPDATE users SET first_name=$1, last_name=$2, email=$3, role=$4, updated_at=NOW()
		WHERE id=$5
	`, u.FirstName, u.LastName, u.Email, u.Role, u.ID)
	return err
}

func (d *Database) UpdateUserPassword(id int, hash string) error {
	_, err := d.db.Exec(`UPDATE users SET password_hash=$1, updated_at=NOW() WHERE id=$2`, hash, id)
	return err
}

func (d *Database) UpdateUserMFA(id int, enabled bool, mfaType, secret string) error {
	_, err := d.db.Exec(`
		UPDATE users SET mfa_enabled=$1, mfa_type=$2, mfa_secret=$3, updated_at=NOW()
		WHERE id=$4
	`, enabled, mfaType, secret, id)
	return err
}

func (d *Database) UpdateLastLogin(id int) error {
	_, err := d.db.Exec(`UPDATE users SET last_login=NOW() WHERE id=$1`, id)
	return err
}

func (d *Database) DeleteUser(id int) error {
	result, err := d.db.Exec(`DELETE FROM users WHERE id=$1`, id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

func (d *Database) SetRecoveryCodes(userID int, codes string) error {
	_, err := d.db.Exec("UPDATE users SET recovery_codes = $1, updated_at = NOW() WHERE id = $2", codes, userID)
	return err
}

func (d *Database) GetRecoveryCodes(userID int) string {
	var codes string
	d.db.QueryRow("SELECT COALESCE(recovery_codes, '') FROM users WHERE id = $1", userID).Scan(&codes)
	return codes
}

func (d *Database) UserCount() int {
	var count int
	d.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	return count
}

func (d *Database) CreatePasswordReset(userID int, token string, expiresAt time.Time) error {
	// Delete old unused tokens for this user
	d.db.Exec("DELETE FROM password_resets WHERE user_id = $1 AND used = FALSE", userID)
	_, err := d.db.Exec(
		"INSERT INTO password_resets (user_id, token, expires_at) VALUES ($1, $2, $3)",
		userID, token, expiresAt,
	)
	return err
}

func (d *Database) ValidateResetToken(token string) (int, error) {
	var userID int
	var expiresAt time.Time
	var used bool
	err := d.db.QueryRow(
		"SELECT user_id, expires_at, used FROM password_resets WHERE token = $1",
		token,
	).Scan(&userID, &expiresAt, &used)
	if err != nil {
		return 0, fmt.Errorf("invalid token")
	}
	if used {
		return 0, fmt.Errorf("token already used")
	}
	if time.Now().After(expiresAt) {
		return 0, fmt.Errorf("token expired")
	}
	return userID, nil
}

func (d *Database) MarkResetTokenUsed(token string) {
	d.db.Exec("UPDATE password_resets SET used = TRUE WHERE token = $1", token)
}

func (d *Database) GetUserByEmail(email string) (*User, error) {
	var u User
	err := d.db.QueryRow(
		"SELECT id, username, password_hash, first_name, last_name, email, role, mfa_enabled, mfa_type, mfa_secret, created_at, updated_at, last_login FROM users WHERE email = $1",
		email,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.FirstName, &u.LastName, &u.Email, &u.Role, &u.MFAEnabled, &u.MFAType, &u.MFASecret, &u.CreatedAt, &u.UpdatedAt, &u.LastLogin)
	if err != nil {
		return nil, err
	}
	return &u, nil
}
