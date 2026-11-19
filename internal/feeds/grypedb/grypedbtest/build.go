// Package grypedbtest builds small Grype v6 databases for tests from the vunnel fixtures in
// internal/feeds/grypedb/testdata.
package grypedbtest

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/anchore/grype/grype/db/v6/testdb"
)

// BuildDB builds a hydrated Grype v6 database stamped with built from the fixture files matching
// includes (doublestar globs or vulnerability IDs; none means every fixture) and returns the
// directory holding vulnerability.db and import.json.
func BuildDB(t *testing.T, built time.Time, includes ...string) (dir string) {
	t.Helper()
	// the builder writes checksums and metadata.json into its input, so work on a copy
	input := filepath.Join(t.TempDir(), "vunnel")
	if err := os.CopyFS(input, os.DirFS(fixtures(t))); err != nil {
		t.Fatalf("grypedbtest: copy fixtures: %v", err)
	}
	// with no includes the builder treats the output as a cache and may skip the build
	globs := []string{"**/*.json"}
	if len(includes) > 0 {
		globs = append([]string(nil), includes...) // the builder rewrites its argument in place
	}
	dir = filepath.Join(t.TempDir(), "db")
	testdb.BuildFromFlatFileDir(t, built, dir, input, globs...)
	return dir
}

// fixtures returns the vunnel fixture directory beside this package.
func fixtures(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("grypedbtest: cannot locate fixtures")
	}
	return filepath.Join(filepath.Dir(file), "..", "testdata", "vunnel")
}
