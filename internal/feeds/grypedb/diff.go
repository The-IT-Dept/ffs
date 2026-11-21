package grypedb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/anchore/grype/grype/db/v6/diff"

	"github.com/the-it-dept/ffs/internal/feeds"
	"github.com/the-it-dept/ffs/internal/subproc"
)

// DiffCommand is the hidden ffs subcommand that runs one diff for ExecDiffer:
// `ffs grypedb-diff --old <dir> --new <dir> --out <file>`.
const DiffCommand = "grypedb-diff"

// DiffNice is how many nice levels below the controller ExecDiffer runs its diffs: a diff of two
// production builds takes minutes of CPU, which matching and the API should not wait behind.
const DiffNice = 10

// diffWaitDelay bounds how long a cancelled diff process may take to exit after it is killed.
const diffWaitDelay = 10 * time.Second

// maxDiffStderr is how much of a diff process's last output an error carries.
const maxDiffStderr = 2 << 10

// diffMemoryShare is the share of the controller's GOMEMLIMIT a diff process gets: a quarter, which
// the controller gives up for as long as the process runs (see shareMemoryLimit). Under the chart's
// 1Gi default that is about 230 MiB, against the 123 MB a diff of two production builds was
// measured at.
const diffMemoryShare = 4

// memLimitMu serialises shareMemoryLimit: the limit is this process's, so diffs take their share one
// at a time.
var memLimitMu sync.Mutex

// Differ diffs two DB directories and returns the packages whose vulnerability records changed
// (see Diff). It may write to oldDir, which is a copy; newDir is the build about to be installed.
type Differ func(ctx context.Context, oldDir, newDir string) ([]PackageKey, error)

// Diff diffs two DB directories in this process and returns the deduplicated, lowercased packages
// whose vulnerability records were added, removed or modified. The differ opens both databases for
// writing (it hydrates them: migrations and ANALYZE), so oldDir must not be a database this process
// holds open read-only (see Feed.changedPackages).
func Diff(_ context.Context, oldDir, newDir string) (_ []PackageKey, err error) {
	d, err := diff.NewDBDiffer(diff.Config{OldDB: oldDir, NewDB: newDir, Include: diff.Includes{Packages: true}})
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := d.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	res, err := d.Diff()
	if err != nil {
		return nil, err
	}
	seen := make(map[PackageKey]bool, len(res.Packages))
	var out []PackageKey
	for _, pd := range res.Packages {
		k := PackageKey{Ecosystem: strings.ToLower(pd.Ecosystem), Name: strings.ToLower(pd.Name)}
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	return out, nil
}

// RunDiff is the DiffCommand: it diffs oldDir and newDir in this process (Diff) and writes the
// changed package keys to out as JSON, through a temporary file and a rename.
func RunDiff(ctx context.Context, oldDir, newDir, out string) error {
	if oldDir == "" || newDir == "" || out == "" {
		return errors.New("grypedb: diff: --old, --new and --out are required")
	}
	keys, err := Diff(ctx, oldDir, newDir)
	if err != nil {
		return err
	}
	if keys == nil {
		keys = []PackageKey{}
	}
	data, err := json.Marshal(keys)
	if err != nil {
		return err
	}
	return feeds.WriteFile(out, data)
}

// ExecDiffer returns a Differ that runs each diff as `<this executable> grypedb-diff` in its own
// process group, nice levels below the controller (at most 19; 0 leaves the priority alone; see
// subproc.Start), so the diff neither competes with the controller at full priority nor shares its
// heap. The process runs in the controller's container, under the same memory limit: it gets its
// own GOMEMLIMIT, a quarter of the controller's, which the controller gives up while it runs (see
// shareMemoryLimit). The process writes the keys to a file beside oldDir, which the Differ reads
// and removes. When ctx ends, the whole process group is killed. A process that fails is an error
// carrying the end of its output.
func ExecDiffer(nice int) Differ {
	return func(ctx context.Context, oldDir, newDir string) ([]PackageKey, error) {
		self, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("locating the ffs executable: %w", err)
		}
		out := strings.TrimRight(oldDir, string(os.PathSeparator)) + ".keys.json"
		if err := os.Remove(out); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		defer func() { _ = os.Remove(out) }()

		limit, restore := shareMemoryLimit()
		defer restore()

		var stderr tailBuffer
		//nolint:gosec // G204: self is this binary, and the directories are the feed's own
		cmd := exec.CommandContext(ctx, self, DiffCommand, "--old", oldDir, "--new", newDir, "--out", out)
		cmd.Env = os.Environ()
		if limit > 0 {
			cmd.Env = append(cmd.Env, "GOMEMLIMIT="+strconv.FormatInt(limit, 10)) // the last one wins
		}
		cmd.Stderr = &stderr
		if err := subproc.Start(cmd, nice, diffWaitDelay); err != nil {
			if pe, ok := errors.AsType[*subproc.PriorityError](err); ok {
				return nil, fmt.Errorf("setting the diff process's priority: %w", pe.Err)
			}
			if ctx.Err() != nil { // done before the start: the same error as a diff cut short
				return nil, context.Cause(ctx)
			}
			return nil, fmt.Errorf("starting the diff process: %w", err)
		}
		err = cmd.Wait()
		if ctx.Err() != nil {
			return nil, context.Cause(ctx)
		}
		if err != nil {
			if msg := strings.TrimSpace(stderr.String()); msg != "" {
				return nil, fmt.Errorf("diff process: %w: %s", err, msg)
			}
			return nil, fmt.Errorf("diff process: %w", err)
		}
		return readKeys(out)
	}
}

// shareMemoryLimit splits this process's GOMEMLIMIT with a diff process: it returns the process's
// share (diffMemoryShare) and lowers this process's limit by as much until restore is called. The
// two then stay within the one limit, which the chart sets to 90% of the container's memory limit:
// they share the container's cgroup, and the kernel kills the whole container when the sum of their
// memory crosses it. GOMEMLIMIT is a soft limit on what each Go runtime maps; the SQLite caches of
// either process are outside it and come out of the remaining 10%. Without a limit (none set, or
// "off") there is nothing to share: the share is 0 and the process inherits the environment as it
// is.
func shareMemoryLimit() (share int64, restore func()) {
	memLimitMu.Lock()
	cur := debug.SetMemoryLimit(-1)
	if cur <= 0 || cur == math.MaxInt64 {
		memLimitMu.Unlock()
		return 0, func() {}
	}
	share = cur / diffMemoryShare
	debug.SetMemoryLimit(cur - share)
	return share, func() {
		debug.SetMemoryLimit(cur)
		memLimitMu.Unlock()
	}
}

// readKeys reads the package keys RunDiff wrote to path.
func readKeys(path string) ([]PackageKey, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: the path is beside the feed's own copy of the current build
	if err != nil {
		return nil, fmt.Errorf("reading the diff result: %w", err)
	}
	var keys []PackageKey
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, fmt.Errorf("reading the diff result: %w", err)
	}
	return keys, nil
}

// tailBuffer keeps the last maxDiffStderr bytes written to it.
type tailBuffer struct{ b []byte }

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if over := len(t.b) - maxDiffStderr; over > 0 {
		t.b = append(t.b[:0], t.b[over:]...)
	}
	return len(p), nil
}

func (t *tailBuffer) String() string { return string(t.b) }
