// Package store opens TrustedCourier's embedded SQLite database. It holds only
// Agent Token hashes and metadata, the Operator Credential hash, and (later)
// Audit Records; never Secrets or Courier Keys (ADR-0001).
package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

// FileName is the database file inside the data directory.
const FileName = "trustedcourier.db"

// migrations are applied in order; PRAGMA user_version records how many ran.
var migrations = []string{
	`CREATE TABLE operator_credential (
		id         INTEGER PRIMARY KEY CHECK (id = 1),
		hash       BLOB    NOT NULL,
		created_at INTEGER NOT NULL
	);
	CREATE TABLE agent_tokens (
		id           TEXT    PRIMARY KEY,
		hash         BLOB    NOT NULL UNIQUE,
		policies     TEXT    NOT NULL,
		created_at   INTEGER NOT NULL,
		expires_at   INTEGER NOT NULL,
		last_used_at INTEGER,
		revoked_at   INTEGER
	);`,
}

// Open creates dataDir if needed, opens the database with owner-only
// permissions, and applies pending migrations.
func Open(ctx context.Context, dataDir string) (*sql.DB, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	path := filepath.Join(dataDir, FileName)
	// Create the file ourselves so SQLite (and its -wal/-shm files, which copy
	// the database's mode) never gets a world-readable default.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create database: %w", err)
	}
	_ = f.Close()

	dsn := (&url.URL{
		Scheme:   "file",
		Path:     path,
		RawQuery: "_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_txlock=immediate",
	}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := migrate(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func migrate(ctx context.Context, db *sql.DB) error {
	var version int
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if version > len(migrations) {
		return fmt.Errorf("database schema version %d is newer than this TrustedCourier (%d)", version, len(migrations))
	}
	for i := version; i < len(migrations); i++ {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply migration %d: %w", i+1, err)
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", i+1)); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
