package grypedb_test

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/feeds/grypedb"
	"github.com/the-it-dept/ffs/internal/feeds/grypedb/grypedbtest"
	"github.com/the-it-dept/ffs/internal/model"
)

// Environment variables that make the stand-in diff process (see TestMain) observable.
const (
	// envReady names a file the process writes "<pid> <grandchild pid or 0> <GOMEMLIMIT>" to once
	// it has started, then waits for envRelease's file before writing no keys and exiting.
	envReady   = "FFS_TEST_DIFF_READY"
	envRelease = "FFS_TEST_DIFF_RELEASE"
	// envGrandchild makes the process first start a child of its own, in its process group, that
	// sleeps (envSleep).
	envGrandchild = "FFS_TEST_DIFF_GRANDCHILD"
	envSleep      = "FFS_TEST_DIFF_SLEEP"
	holdFor       = 2 * time.Minute // how long a held process waits before it gives up
)

// TestMain lets this test binary stand in for the ffs binary that grypedb.ExecDiffer re-executes:
// run as `<binary> grypedb-diff --old … --new … --out …`, it runs the diff command and exits.
func TestMain(m *testing.M) {
	if os.Getenv(envSleep) != "" {
		time.Sleep(holdFor)
		os.Exit(0)
	}
	if len(os.Args) > 1 && os.Args[1] == grypedb.DiffCommand {
		os.Exit(diffCommand(os.Args[2:]))
	}
	os.Exit(m.Run())
}

func diffCommand(args []string) int {
	fs := flag.NewFlagSet(grypedb.DiffCommand, flag.ContinueOnError)
	oldDir, newDir, out := fs.String("old", "", ""), fs.String("new", "", ""), fs.String("out", "", "")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if ready := os.Getenv(envReady); ready != "" {
		return held(ready, os.Getenv(envRelease), *out)
	}
	if err := grypedb.RunDiff(context.Background(), *oldDir, *newDir, *out); err != nil {
		fmt.Fprintln(os.Stderr, "ffs:", err)
		return 1
	}
	return 0
}

// held is the stand-in diff process of the envReady mode.
func held(ready, release, out string) int {
	grandchild := 0
	if os.Getenv(envGrandchild) != "" {
		self, err := os.Executable()
		if err != nil {
			return 1
		}
		cmd := exec.CommandContext(context.Background(), self) //nolint:gosec // G204: this test binary
		cmd.Env = append(os.Environ(), envSleep+"=1")
		if err := cmd.Start(); err != nil {
			return 1
		}
		grandchild = cmd.Process.Pid
	}
	report := fmt.Sprintf("%d %d %s", os.Getpid(), grandchild, os.Getenv("GOMEMLIMIT"))
	//nolint:gosec // G703: the path is a temp file of the test that started this process
	if err := os.WriteFile(ready+".tmp", []byte(report), 0o600); err != nil || os.Rename(ready+".tmp", ready) != nil {
		return 1
	}
	for deadline := time.Now().Add(holdFor); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if _, err := os.Stat(release); err == nil { //nolint:gosec // G703: a temp file of the test that started this process
			if os.WriteFile(out, []byte("[]"), 0o600) != nil {
				return 1
			}
			return 0
		}
	}
	return 1
}

// startHeld runs differ in the background with the stand-in process held (see envReady) and returns
// its report once it has started, and a channel that receives the differ's error. Creating release
// lets the process finish. However the test ends, its cleanup releases the process, cancels the
// differ's context and waits for the differ, so a failed test leaves no process behind.
func startHeld(t *testing.T, c context.Context, differ grypedb.Differ, grandchild bool) (pid, grandchildPID int, limit, release string, done <-chan error) {
	t.Helper()
	dir := t.TempDir()
	ready := filepath.Join(dir, "ready")
	release = filepath.Join(dir, "release")
	t.Setenv(envReady, ready)
	t.Setenv(envRelease, release)
	if grandchild {
		t.Setenv(envGrandchild, "1")
	}
	c, cancel := context.WithCancel(c)
	errc := make(chan error, 1)
	finished := make(chan struct{})
	newDir := t.TempDir()
	go func() {
		defer close(finished)
		_, err := differ(c, filepath.Join(dir, "old"), newDir)
		errc <- err
	}()
	t.Cleanup(func() {
		_ = os.WriteFile(release, nil, 0o600)
		cancel()
		select {
		case <-finished:
		case <-time.After(30 * time.Second):
			t.Error("the Differ did not return after its release and cancel")
		}
	})
	var report []byte
	require.Eventually(t, func() bool {
		var err error
		report, err = os.ReadFile(ready) //nolint:gosec // G304: the test's own temp file
		return err == nil
	}, time.Minute, 10*time.Millisecond, "the diff process starts")
	fields := strings.SplitN(string(report)+" ", " ", 3)
	pid, err := strconv.Atoi(fields[0])
	require.NoError(t, err)
	grandchildPID, err = strconv.Atoi(fields[1])
	require.NoError(t, err)
	return pid, grandchildPID, strings.TrimSpace(fields[2]), release, errc
}

// copyDB copies a DB directory, as the feed does before a diff, which may write to it.
func copyDB(t *testing.T, dir string) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "old")
	require.NoError(t, os.CopyFS(dst, os.DirFS(dir)))
	return dst
}

// TestExecDiffer_RoundTripsPackageKeys (#7): the diff run in a re-executed process at nice 10
// returns the package keys an in-process diff does, through its result file, which it removes.
func TestExecDiffer_RoundTripsPackageKeys(t *testing.T) {
	oldDir := grypedbtest.BuildDB(t, built1, "**/debian-12/cve-2022-38178.json")
	newDir := grypedbtest.BuildDB(t, built2)

	oldCopy := copyDB(t, oldDir)
	got, err := grypedb.ExecDiffer(grypedb.DiffNice)(ctx, oldCopy, newDir)
	require.NoError(t, err)
	require.Contains(t, got, grypedb.PackageKey{Ecosystem: "deb", Name: "firefox-esr"})
	require.Contains(t, got, grypedb.PackageKey{Ecosystem: "deb", Name: "thunderbird"})
	require.NotContains(t, got, grypedb.PackageKey{Ecosystem: "deb", Name: "bind9"})
	require.NoFileExists(t, oldCopy+".keys.json")

	want, err := grypedb.Diff(ctx, copyDB(t, oldDir), newDir)
	require.NoError(t, err)
	require.ElementsMatch(t, want, got)
}

// TestExecDiffer_FailureIsAnError: a diff process that fails is an error carrying its output.
func TestExecDiffer_FailureIsAnError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nothing")
	_, err := grypedb.ExecDiffer(0)(ctx, missing, grypedbtest.BuildDB(t, built1))
	require.ErrorContains(t, err, "diff process: exit status 1: ffs: ")
	require.NoFileExists(t, missing+".keys.json")
}

// TestExecDiffer_CancelKillsTheProcessGroup (W53): cancelling a running diff kills its whole process
// group, a process the diff started included, and the Differ returns the context's cause.
func TestExecDiffer_CancelKillsTheProcessGroup(t *testing.T) {
	c, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	pid, grandchild, _, _, done := startHeld(t, c, grypedb.ExecDiffer(grypedb.DiffNice), true)
	require.NotZero(t, grandchild)
	require.NoError(t, syscall.Kill(-pid, 0), "the process group is running")

	stop := errors.New("shutting down")
	cancel(stop)
	select {
	case err := <-done:
		require.ErrorIs(t, err, stop)
	case <-time.After(30 * time.Second):
		t.Fatal("the Differ did not return after the cancel")
	}
	gone := func(target int) func() bool {
		return func() bool { return errors.Is(syscall.Kill(target, 0), syscall.ESRCH) }
	}
	require.Eventually(t, gone(-pid), 10*time.Second, 10*time.Millisecond, "the process group is gone")
	require.Eventually(t, gone(grandchild), 10*time.Second, 10*time.Millisecond, "the grandchild is gone")

	// A context that is done before the diff starts never starts a process.
	_, err := grypedb.ExecDiffer(grypedb.DiffNice)(c, filepath.Join(t.TempDir(), "old"), t.TempDir())
	require.ErrorIs(t, err, stop)
}

// TestExecDiffer_SharesTheMemoryLimit (W18): the diff process gets a quarter of this process's
// GOMEMLIMIT, and this process gives that quarter up until the diff ends, so the two stay within the
// container's one limit. Without a limit, there is nothing to share.
func TestExecDiffer_SharesTheMemoryLimit(t *testing.T) {
	prev := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(prev) })

	t.Run("limit", func(t *testing.T) {
		const limit = int64(1 << 30)
		debug.SetMemoryLimit(limit)
		_, _, child, release, done := startHeld(t, ctx, grypedb.ExecDiffer(0), false)
		require.Equal(t, strconv.FormatInt(limit/4, 10), child, "the diff process's GOMEMLIMIT")
		require.Equal(t, limit-limit/4, debug.SetMemoryLimit(-1), "this process's, while the diff runs")
		require.NoError(t, os.WriteFile(release, nil, 0o600))
		require.NoError(t, <-done)
		require.Equal(t, limit, debug.SetMemoryLimit(-1), "restored when the diff ends")
	})

	t.Run("no limit", func(t *testing.T) {
		debug.SetMemoryLimit(math.MaxInt64)
		t.Setenv("GOMEMLIMIT", "")
		_, _, child, release, done := startHeld(t, ctx, grypedb.ExecDiffer(0), false)
		require.Empty(t, child)
		require.Equal(t, int64(math.MaxInt64), debug.SetMemoryLimit(-1))
		require.NoError(t, os.WriteFile(release, nil, 0o600))
		require.NoError(t, <-done)
	})
}

// TestGrypeDB_DiffTimeout (W17): a diff may take twice the feed's interval, and never less than an
// hour.
func TestGrypeDB_DiffTimeout(t *testing.T) {
	for _, tc := range []struct{ interval, want time.Duration }{
		{10 * time.Minute, time.Hour},
		{time.Hour, 2 * time.Hour},
	} {
		t.Run(tc.interval.String(), func(t *testing.T) {
			fx := newFixture(t)
			var budget time.Duration
			differ := func(c context.Context, oldDir, newDir string) ([]grypedb.PackageKey, error) {
				dl, ok := c.Deadline()
				require.True(t, ok)
				budget = time.Until(dl)
				return grypedb.Diff(c, oldDir, newDir)
			}
			fx.feed = grypedb.New(grypedb.Options{
				Config:  config.FeedConfig{Enabled: true, URL: fx.srv.listingURL(), Interval: tc.interval, StaleAfter: 48 * time.Hour},
				DataDir: fx.dataDir, Store: fx.st, HTTP: fx.srv.Client(), Handler: fx.h.handle, Now: func() time.Time { return now },
				Diff: differ,
			})
			fx.srv.publish(t, grypedbtest.BuildDB(t, built1), built1)
			require.NoError(t, fx.feed.Sync(ctx))
			fx.srv.publish(t, grypedbtest.BuildDB(t, built2), built2)
			require.NoError(t, fx.feed.Sync(ctx))
			require.InDelta(t, tc.want.Seconds(), budget.Seconds(), time.Minute.Seconds())
		})
	}
}

// TestGrypeDB_SubprocessDiffWhileTheMatcherHoldsTheCurrentDB: with the diff in its own process, as
// the controller runs it, the update still diffs a copy of the build the matcher holds open, and
// the copy is gone afterwards.
func TestGrypeDB_SubprocessDiffWhileTheMatcherHoldsTheCurrentDB(t *testing.T) {
	fx := newFixture(t)
	fx.feed = grypedb.New(grypedb.Options{
		Config:  config.FeedConfig{Enabled: true, URL: fx.srv.listingURL(), Interval: time.Hour, StaleAfter: 48 * time.Hour},
		DataDir: fx.dataDir, Store: fx.st, HTTP: fx.srv.Client(), Handler: fx.h.handle, Now: func() time.Time { return now },
		Diff: grypedb.ExecDiffer(grypedb.DiffNice),
	})
	fx.srv.publish(t, grypedbtest.BuildDB(t, built1, "**/debian-12/cve-2022-38178.json"), built1)
	require.NoError(t, fx.feed.Sync(ctx))
	rdr, err := v6.NewReader(v6.Config{DBDirPath: fx.h.updates[0].Path}) // as internal/match/grype opens it
	require.NoError(t, err)
	t.Cleanup(func() { _ = rdr.Close() })

	fx.srv.publish(t, grypedbtest.BuildDB(t, built2), built2)
	require.NoError(t, fx.feed.Sync(ctx))
	require.Len(t, fx.h.updates, 2)
	require.False(t, fx.h.updates[1].Full)
	require.Contains(t, fx.h.updates[1].Changed, grypedb.PackageKey{Ecosystem: "deb", Name: "firefox-esr"})
	require.ElementsMatch(t, []string{built2.Format("20060102T150405Z"), built1.Format("20060102T150405Z")}, fx.dbDirs(t),
		"the copy and its result file are removed")
}

// countingDiffer counts the diffs it runs, failing them with fail when set.
type countingDiffer struct {
	runs atomic.Int32
	fail error
}

func (c *countingDiffer) diff(ctx context.Context, oldDir, newDir string) ([]grypedb.PackageKey, error) {
	c.runs.Add(1)
	if c.fail != nil {
		return nil, c.fail
	}
	return grypedb.Diff(ctx, oldDir, newDir)
}

// catalogued stores n catalogued images an owner runs.
func (fx *fixture) catalogued(t *testing.T, n int) {
	t.Helper()
	var uses []model.ContainerUse
	for i := range n {
		d := fmt.Sprintf("sha256:%064d", i)
		require.NoError(t, fx.st.UpsertImage(ctx, model.Image{Digest: d, Repo: "ghcr.io/example/app", Status: model.ImageCatalogued}))
		uses = append(uses, model.ContainerUse{Name: fmt.Sprintf("c%d", i), Digest: d})
	}
	require.NoError(t, fx.st.UpsertOwner(ctx, model.Owner{Ref: model.OwnerRef{Kind: "Deployment", Namespace: "shop", Name: "web"},
		Containers: uses}))
}

// TestGrypeDB_DiffMinImages (#7): with fewer catalogued SBOMs than diffMinImages, a new build is a
// full re-match and no diff runs; with as many, the diff runs. A failed diff fails the sync, as
// before.
func TestGrypeDB_DiffMinImages(t *testing.T) {
	for name, tc := range map[string]struct {
		images, min int
		diffs       int32
		full        bool
	}{
		"below":     {images: 2, min: 3, diffs: 0, full: true},
		"at":        {images: 3, min: 3, diffs: 1, full: false},
		"always":    {images: 0, min: 0, diffs: 1, full: false},
		"one below": {images: 0, min: 1, diffs: 0, full: true},
	} {
		t.Run(name, func(t *testing.T) {
			fx := newFixture(t)
			fx.catalogued(t, tc.images)
			d := &countingDiffer{}
			fx.feed = grypedb.New(grypedb.Options{
				Config:  config.FeedConfig{Enabled: true, URL: fx.srv.listingURL(), Interval: time.Hour, StaleAfter: 48 * time.Hour},
				DataDir: fx.dataDir, Store: fx.st, HTTP: fx.srv.Client(), Handler: fx.h.handle, Now: func() time.Time { return now },
				Diff: d.diff, DiffMinImages: tc.min,
			})
			fx.srv.publish(t, grypedbtest.BuildDB(t, built1, "**/debian-12/cve-2022-38178.json"), built1)
			require.NoError(t, fx.feed.Sync(ctx))
			require.True(t, fx.h.updates[0].Full, "the first install is full")
			require.Zero(t, d.runs.Load())

			fx.srv.publish(t, grypedbtest.BuildDB(t, built2), built2)
			require.NoError(t, fx.feed.Sync(ctx))
			require.Len(t, fx.h.updates, 2)
			u := fx.h.updates[1]
			require.Equal(t, tc.diffs, d.runs.Load())
			require.Equal(t, tc.full, u.Full)
			if tc.full {
				require.Empty(t, u.Changed)
			} else {
				require.Contains(t, u.Changed, grypedb.PackageKey{Ecosystem: "deb", Name: "firefox-esr"})
			}
		})
	}

	t.Run("diff fails", func(t *testing.T) {
		fx := newFixture(t)
		d := &countingDiffer{fail: errors.New("diff process: signal: killed")}
		fx.feed = grypedb.New(grypedb.Options{
			Config:  config.FeedConfig{Enabled: true, URL: fx.srv.listingURL(), Interval: time.Hour, StaleAfter: 48 * time.Hour},
			DataDir: fx.dataDir, Store: fx.st, HTTP: fx.srv.Client(), Handler: fx.h.handle, Now: func() time.Time { return now },
			Diff: d.diff,
		})
		fx.srv.publish(t, grypedbtest.BuildDB(t, built1), built1)
		require.NoError(t, fx.feed.Sync(ctx))
		fx.srv.publish(t, grypedbtest.BuildDB(t, built2), built2)
		require.ErrorContains(t, fx.feed.Sync(ctx), "grypedb: diff: diff process: signal: killed")
		require.Len(t, fx.h.updates, 1)
		require.Equal(t, built1.Format(time.RFC3339), fx.state(t).Watermark)
	})
}
