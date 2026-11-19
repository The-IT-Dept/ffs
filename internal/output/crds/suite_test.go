package crds

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
	"github.com/the-it-dept/ffs/internal/testenv"
)

const (
	cve        = "CVE-2026-41873"
	ghsa       = "GHSA-aaaa-bbbb-cccc"
	debianRepo = "docker.io/library/debian"
)

var (
	ctx = context.Background()
	t0  = time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	env *testenv.Env // nil under -short
)

func TestMain(m *testing.M) {
	flag.Parse()
	ctrllog.SetLogger(logr.Discard())
	if testing.Short() {
		os.Exit(m.Run())
	}
	e, err := testenv.New()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, ns := range []string{"web", "ffs"} {
		if err := e.EnsureNamespace(ctx, ns); err != nil {
			fmt.Fprintln(os.Stderr, err)
			_ = e.Stop()
			os.Exit(1)
		}
	}
	env = e
	code := m.Run()
	if err := env.Stop(); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	os.Exit(code)
}

// needEnv skips tests that need the API server under -short.
func needEnv(t *testing.T) {
	t.Helper()
	if env == nil {
		t.Skip("envtest")
	}
}

func newStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "ffs.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	return st
}

// seedAdvisory stores cve with its GHSA alias.
func seedAdvisory(t *testing.T, st *store.Store) {
	t.Helper()
	require.NoError(t, st.UpsertAdvisory(ctx, model.Advisory{ID: cve, Aliases: []string{ghsa}, Title: "openssl: buffer overflow",
		Links: []string{"https://www.cve.org/CVERecord?id=" + cve}, Published: t0.Add(-48 * time.Hour), Observed: t0.Add(-24 * time.Hour),
		CNASeverity: model.SeverityCritical, CNACVSS: 9.8}))
}

func deployment(ns, name string) model.OwnerRef {
	return model.OwnerRef{Kind: "Deployment", Namespace: ns, Name: name, UID: "uid-" + name}
}

// openFinding is an open finding of o on advisory in repo.
func openFinding(o model.OwnerRef, repo, advisory string, p model.Priority, matched time.Time) model.Finding {
	return model.Finding{
		Fingerprint: model.FindingFingerprint("default", o, repo, advisory),
		Owner:       o, ImageRepo: repo, AdvisoryID: advisory,
		Packages: []model.FindingPackage{{Name: "openssl", Ecosystem: "deb", Installed: "3.0.15-1~deb12u1",
			Fixed: []string{"3.0.17-1~deb12u1"}, Path: "/var/lib/dpkg/status.d/openssl"}},
		Digests:  []string{"sha256:d1"},
		Severity: model.SeverityCritical, SeveritySource: "debian",
		FixState: model.FixFixed, FixAvailable: true,
		Priority: p, Reasons: []string{"exposed via Service web/" + o.Name + " (LoadBalancer)"},
		State:     model.StateOpen,
		Published: t0.Add(-48 * time.Hour), Observed: t0.Add(-24 * time.Hour), Matched: matched, LastSeen: matched,
	}
}

func apply(t *testing.T, st *store.Store, fs ...model.Finding) {
	t.Helper()
	require.NoError(t, st.ApplyFindings(ctx, fs, nil))
}
