package banpool

//go:generate mockgen -source=repository.go -destination=mocks/repository_mock.go -package=mocks

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const createTableQuery = `
CREATE TABLE IF NOT EXISTS bans (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	ip TEXT NOT NULL UNIQUE,
	banned_at TIMESTAMP NOT NULL,
	banned_until TIMESTAMP NOT NULL
)`

// DB abstracts the subset of *sql.DB used by the repository so it can be mocked.
type DB interface {
	Exec(query string, args ...any) (sql.Result, error)
	QueryRow(query string, args ...any) *sql.Row
	Query(query string, args ...any) (*sql.Rows, error)
	Close() error
}

type Repository interface {
	Add(ban *Ban) (int64, error)
	Get(ip string) (*Ban, error)
	GetBanned() ([]*Ban, error)
	GetExpired() ([]*Ban, error)
	Update(ban *Ban) error
	Delete(id int64) error
	Close() error
}

type repository struct {
	db DB
}

func NewRepository(databasePath string) (Repository, error) {
	if err := os.MkdirAll(filepath.Dir(databasePath), 0755); err != nil {
		return nil, fmt.Errorf("banpool.NewRepository(databasePath: %s) -> %w: %v", databasePath, ErrCantCreateDatabaseDir, err)
	}

	db, err := sql.Open("sqlite3", databasePath)
	if err != nil {
		return nil, fmt.Errorf("banpool.NewRepository(databasePath: %s) -> %w: %v", databasePath, ErrCantOpenDatabase, err)
	}

	if _, err := db.Exec(createTableQuery); err != nil {
		db.Close()
		return nil, fmt.Errorf("banpool.NewRepository(databasePath: %s) -> %w: %v", databasePath, ErrCantCreateTable, err)
	}

	return &repository{db: db}, nil
}

func (r *repository) Add(ban *Ban) (int64, error) {
	result, err := r.db.Exec(
		"INSERT INTO bans (ip, banned_at, banned_until) VALUES (?, ?, ?)",
		ban.IP, ban.BannedAt, ban.BannedUntil,
	)
	if err != nil {
		return 0, fmt.Errorf("banpool.repository.Add(ip: %s) -> %w: %v", ban.IP, ErrCantAddBan, err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("banpool.repository.Add(ip: %s) -> %w: %v", ban.IP, ErrCantAddBan, err)
	}

	return id, nil
}

func (r *repository) Get(ip string) (*Ban, error) {
	ban := &Ban{}

	err := r.db.QueryRow(
		"SELECT id, ip, banned_at, banned_until FROM bans WHERE ip = ?", ip,
	).Scan(&ban.ID, &ban.IP, &ban.BannedAt, &ban.BannedUntil)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("banpool.repository.Get(ip: %s) -> %w", ip, ErrBanNotFound)
	}

	if err != nil {
		return nil, fmt.Errorf("banpool.repository.Get(ip: %s) -> %w: %v", ip, ErrCantGetBan, err)
	}

	return ban, nil
}

func (r *repository) GetBanned() ([]*Ban, error) {
	rows, err := r.db.Query(
		"SELECT id, ip, banned_at, banned_until FROM bans WHERE banned_until > ?", time.Now(),
	)
	if err != nil {
		return nil, fmt.Errorf("banpool.repository.GetBanned() -> %w: %v", ErrCantGetBannedIPs, err)
	}
	defer rows.Close()

	bans := []*Ban{}

	for rows.Next() {
		ban := &Ban{}

		if err := rows.Scan(&ban.ID, &ban.IP, &ban.BannedAt, &ban.BannedUntil); err != nil {
			return nil, fmt.Errorf("banpool.repository.GetBanned() -> %w: %v", ErrCantGetBannedIPs, err)
		}

		bans = append(bans, ban)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("banpool.repository.GetBanned() -> %w: %v", ErrCantGetBannedIPs, err)
	}

	return bans, nil
}

func (r *repository) Update(ban *Ban) error {
	result, err := r.db.Exec(
		"UPDATE bans SET ip = ?, banned_at = ?, banned_until = ? WHERE id = ?",
		ban.IP, ban.BannedAt, ban.BannedUntil, ban.ID,
	)
	if err != nil {
		return fmt.Errorf("banpool.repository.Update(id: %d, ip: %s) -> %w: %v", ban.ID, ban.IP, ErrCantUpdateBan, err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("banpool.repository.Update(id: %d, ip: %s) -> %w: %v", ban.ID, ban.IP, ErrCantUpdateBan, err)
	}

	if affected == 0 {
		return fmt.Errorf("banpool.repository.Update(id: %d, ip: %s) -> %w", ban.ID, ban.IP, ErrBanNotFound)
	}

	return nil
}

func (r *repository) Delete(id int64) error {
	if _, err := r.db.Exec("DELETE FROM bans WHERE id = ?", id); err != nil {
		return fmt.Errorf("banpool.repository.Delete(id: %d) -> %w: %v", id, ErrCantDeleteBan, err)
	}

	return nil
}

func (r *repository) GetExpired() ([]*Ban, error) {
	rows, err := r.db.Query(
		"SELECT id, ip, banned_at, banned_until FROM bans WHERE banned_until <= ?", time.Now(),
	)
	if err != nil {
		return nil, fmt.Errorf("banpool.repository.GetExpired() -> %w: %v", ErrCantGetBannedIPs, err)
	}
	defer rows.Close()

	bans := []*Ban{}

	for rows.Next() {
		ban := &Ban{}

		if err := rows.Scan(&ban.ID, &ban.IP, &ban.BannedAt, &ban.BannedUntil); err != nil {
			return nil, fmt.Errorf("banpool.repository.GetExpired() -> %w: %v", ErrCantGetBannedIPs, err)
		}

		bans = append(bans, ban)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("banpool.repository.GetExpired() -> %w: %v", ErrCantGetBannedIPs, err)
	}

	return bans, nil
}

func (r *repository) Close() error {
	return r.db.Close()
}
