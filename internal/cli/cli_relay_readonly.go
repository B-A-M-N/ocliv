package cli

import (
	"database/sql"
	"fmt"
	"net/url"
	"path/filepath"

	"ocliv/internal/store"
)

// openRelayDBReadOnly opens an existing relay database without invoking the
// migration-capable store.Open path. Observation commands must never create,
// migrate, or otherwise change the live database.
func openRelayDBReadOnly(dataDir string) (*sql.DB, error) {
	path, err := filepath.Abs(filepath.Join(dataDir, "ocliv.db"))
	if err != nil {
		return nil, err
	}
	uri := (&url.URL{Scheme: "file", Path: path}).String() + "?mode=ro"
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	var version int
	if err := db.QueryRow(`SELECT MAX(v) FROM schema_version`).Scan(&version); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("not an ocliv relay database (%s): %w", path, err)
	}
	if version < 1 {
		_ = db.Close()
		return nil, fmt.Errorf("invalid relay database schema version %d", version)
	}
	if version > store.SchemaVersion {
		_ = db.Close()
		return nil, fmt.Errorf("database schema version %d is newer than this binary knows (%d)", version, store.SchemaVersion)
	}
	return db, nil
}
