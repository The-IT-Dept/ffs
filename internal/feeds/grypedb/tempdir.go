package grypedb

import (
	"fmt"
	"os"
	"path/filepath"
)

// SQLiteTempDirEnv is the variable SQLite reads first for the directory of its temporary files.
const SQLiteTempDirEnv = "SQLITE_TMPDIR"

// UseSQLiteTempDir points SQLite's temporary files at dataDir/tmp, unless SQLITE_TMPDIR is already
// set, creates that directory and returns it. A directory it chose itself is emptied first.
//
// Hydrating a Grype DB build and diffing two of them spill gigabytes of temporary tables and sort
// runs to disk. SQLite otherwise falls back to TMPDIR or /tmp, which in the chart is a small
// emptyDir outside the persistent volume. SQLite also skips a directory that does not exist, so the
// directory must exist before the first temporary file.
//
// The SQLite runtime copies the environment when it opens its first connection: call this before
// anything opens a database.
func UseSQLiteTempDir(dataDir string) (string, error) {
	dir := os.Getenv(SQLiteTempDirEnv)
	if dir == "" {
		if dataDir == "" {
			return "", fmt.Errorf("grypedb: SQLite temp directory: no data directory")
		}
		dir = filepath.Join(dataDir, "tmp")
		// SQLite unlinks its temporary files as it creates them, so anything here is left over.
		if err := os.RemoveAll(dir); err != nil {
			return "", fmt.Errorf("grypedb: SQLite temp directory: %w", err)
		}
		if err := os.Setenv(SQLiteTempDirEnv, dir); err != nil {
			return "", fmt.Errorf("grypedb: SQLite temp directory: %w", err)
		}
	}
	//nolint:gosec // G703: the operator's SQLITE_TMPDIR or a fixed name under the configured data directory
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("grypedb: SQLite temp directory: %w", err)
	}
	return dir, nil
}
