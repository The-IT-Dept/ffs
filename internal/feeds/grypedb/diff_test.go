package grypedb_test

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/feeds/grypedb"
	"github.com/the-it-dept/ffs/internal/feeds/grypedb/grypedbtest"
	"github.com/the-it-dept/ffs/internal/model"
)

// TestMain lets this test binary stand in for the ffs binary that grypedb.ExecDiffer re-executes:
// run as `<binary> grypedb-diff --old … --new … --out …`, it runs the diff command and exits.
func TestMain(m *testing.M) {
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
	if err := grypedb.RunDiff(context.Background(), *oldDir, *newDir, *out); err != nil {
		fmt.Fprintln(os.Stderr, "ffs:", err)
		return 1
	}
	return 0
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

// TestExecDiffer_Cancelled: a cancelled diff ends with the context's error.
func TestExecDiffer_Cancelled(t *testing.T) {
	c, cancel := context.WithCancel(ctx)
	cancel()
	_, err := grypedb.ExecDiffer(grypedb.DiffNice)(c, filepath.Join(t.TempDir(), "old"), t.TempDir())
	require.ErrorIs(t, err, context.Canceled)
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
