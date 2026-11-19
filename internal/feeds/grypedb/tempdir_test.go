package grypedb_test

import (
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	_ "github.com/glebarez/go-sqlite" // the store's SQLite driver
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/feeds/grypedb"
)

func TestUseSQLiteTempDir_DefaultsUnderDataDir(t *testing.T) {
	t.Setenv(grypedb.SQLiteTempDirEnv, "")
	dataDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dataDir, "tmp"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "tmp", "etilqs_left"), []byte("x"), 0o600))

	dir, err := grypedb.UseSQLiteTempDir(dataDir)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(dataDir, "tmp"), dir)
	require.Equal(t, dir, os.Getenv(grypedb.SQLiteTempDirEnv))
	require.DirExists(t, dir)
	require.NoFileExists(t, filepath.Join(dir, "etilqs_left"), "leftovers are removed")
}

func TestUseSQLiteTempDir_KeepsAnOperatorSetting(t *testing.T) {
	own := filepath.Join(t.TempDir(), "sqlite-tmp")
	t.Setenv(grypedb.SQLiteTempDirEnv, own)

	dir, err := grypedb.UseSQLiteTempDir(t.TempDir())
	require.NoError(t, err)
	require.Equal(t, own, dir)
	require.Equal(t, own, os.Getenv(grypedb.SQLiteTempDirEnv))
	require.DirExists(t, own, "created so SQLite does not skip it")
}

// TestUseSQLiteTempDir_SQLiteSpillsThere runs a child process that calls UseSQLiteTempDir before
// opening a database, spills a temporary table to disk, and checks through /proc that the open
// temporary file is in the data directory. SQLite unlinks its temporary files on creation, so only
// /proc (Linux) shows where they are.
func TestUseSQLiteTempDir_SQLiteSpillsThere(t *testing.T) {
	if dataDir := os.Getenv("FFS_TEST_SQLITE_TMPDIR_CHILD"); dataDir != "" {
		sqliteSpillChild(t, dataDir)
		return
	}
	if runtime.GOOS != "linux" {
		t.Skip("needs /proc/self/fd")
	}
	dataDir := t.TempDir()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestUseSQLiteTempDir_SQLiteSpillsThere$", "-test.count=1") //nolint:gosec // G204: re-runs this test binary
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, grypedb.SQLiteTempDirEnv+"=") && !strings.HasPrefix(kv, "TMPDIR=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env, "FFS_TEST_SQLITE_TMPDIR_CHILD="+dataDir)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", out)
	require.Contains(t, string(out), "temp file under data dir")
}

func sqliteSpillChild(t *testing.T, dataDir string) {
	dir, err := grypedb.UseSQLiteTempDir(dataDir)
	require.NoError(t, err)
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "spill.db"))
	require.NoError(t, err)
	defer func() { require.NoError(t, db.Close()) }()
	db.SetMaxOpenConns(1)
	for _, q := range []string{
		"PRAGMA temp_store = FILE",
		"PRAGMA cache_size = 16",
		"CREATE TEMP TABLE spill(v TEXT)",
		"WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 20000) INSERT INTO spill SELECT printf('%0200d', i) FROM n",
	} {
		_, err := db.ExecContext(ctx, q)
		require.NoError(t, err, q)
	}
	fds, err := os.ReadDir("/proc/self/fd")
	require.NoError(t, err)
	var targets []string
	for _, fd := range fds {
		if target, err := os.Readlink(filepath.Join("/proc/self/fd", fd.Name())); err == nil {
			targets = append(targets, target)
			if strings.HasPrefix(target, dir+string(filepath.Separator)) {
				fmt.Println("temp file under data dir:", target)
				return
			}
		}
	}
	t.Fatalf("no open file under %s; open files: %v", dir, targets)
}
