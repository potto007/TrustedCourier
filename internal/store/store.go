// Package store opens TrustedCourier's embedded SQLite database. It holds only
// Agent Token hashes and metadata, the Operator Credential hash, Audit
// Records, and their signed checkpoints; never Secrets or Courier Keys
// (ADR-0001, ADR-0009).
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

// FileName is the database file inside the data directory.
const FileName = "trustedcourier.db"

// migrations are applied in order; PRAGMA user_version records how many ran.
// Timestamps are Unix milliseconds.
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
	`CREATE TABLE audit_records (
		seq             INTEGER PRIMARY KEY,
		time            INTEGER NOT NULL,
		agent_token_id  TEXT    NOT NULL,
		secret_name     TEXT    NOT NULL,
		delivery        TEXT    NOT NULL,
		upstream        TEXT    NOT NULL,
		upstream_host   TEXT    NOT NULL,
		decision        TEXT    NOT NULL,
		reason          TEXT    NOT NULL,
		upstream_status INTEGER,
		failure         TEXT    NOT NULL,
		prev_hash       BLOB    NOT NULL,
		hash            BLOB    NOT NULL
	);`,
	`CREATE TABLE audit_checkpoints (
		seq       INTEGER PRIMARY KEY,
		prev_seq  INTEGER NOT NULL,
		time      INTEGER NOT NULL,
		head      BLOB    NOT NULL,
		signature BLOB    NOT NULL
	);`,
}

// Open creates dataDir if needed, restricts it and the database files to
// the owner, and applies pending migrations. dataDir must be absolute.
func Open(ctx context.Context, dataDir string) (*sql.DB, error) {
	if !filepath.IsAbs(dataDir) {
		return nil, fmt.Errorf("data directory %q is not an absolute path", dataDir)
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	path := filepath.Join(dataDir, FileName)
	// Create the file ourselves so SQLite never gets a world-readable
	// default, and tighten modes an existing installation may have loosened.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create database: %w", err)
	}
	_ = f.Close()
	if err := restrict(dataDir, path); err != nil {
		return nil, err
	}

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

func restrict(dataDir, dbPath string) error {
	if err := os.Chmod(dataDir, 0o700); err != nil {
		return fmt.Errorf("restrict data directory: %w", err)
	}
	for _, p := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		if err := os.Chmod(p, 0o600); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("restrict database file: %w", err)
		}
	}
	return nil
}

// migrate applies pending migrations one transaction at a time. Each
// transaction takes SQLite's write lock (_txlock=immediate) before reading
// the schema version, so concurrent opens cannot apply the same migration.
func migrate(ctx context.Context, db *sql.DB) error {
	for {
		done, err := migrateOnce(ctx, db)
		if err != nil || done {
			return err
		}
	}
}

func migrateOnce(ctx context.Context, db *sql.DB) (done bool, err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()

	var version int
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return false, fmt.Errorf("read schema version: %w", err)
	}
	switch {
	case version > len(migrations):
		return false, fmt.Errorf("database schema version %d is newer than this TrustedCourier (%d)", version, len(migrations))
	case version == len(migrations):
		return true, nil
	}
	if _, err := tx.ExecContext(ctx, migrations[version]); err != nil {
		return false, fmt.Errorf("apply migration %d: %w", version+1, err)
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", version+1)); err != nil {
		return false, err
	}
	return false, tx.Commit()
}
