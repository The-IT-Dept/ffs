package engine_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/engine"
	"github.com/the-it-dept/ffs/internal/feeds/grypedb"
	"github.com/the-it-dept/ffs/internal/feeds/osv"
	"github.com/the-it-dept/ffs/internal/findings"
	"github.com/the-it-dept/ffs/internal/match"
	"github.com/the-it-dept/ffs/internal/match/osvfast"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

var (
	ctx = context.Background()
	t0  = time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
)

const (
	d1       = "sha256:d1"
	d2       = "sha256:d2"
	cve      = "CVE-2026-41873"
	apiKey   = "Deployment/web/api"
	cartKey  = "Deployment/shop/cart"
	apiRepo  = "registry.example.com/web/api"
	cartRepo = "registry.example.com/shop/cart"
)

var (
	apiRef  = model.OwnerRef{Kind: "Deployment", Namespace: "web", Name: "api", UID: "uid-api"}
	cartRef = model.OwnerRef{Kind: "Deployment", Namespace: "shop", Name: "cart", UID: "uid-cart"}
	debian  = &model.Distro{ID: "debian", VersionID: "12", Codename: "bookworm"}
)

// spyStore records the scope of every ReplaceMatches call.
type spyStore struct {
	*store.Store
	replaced []store.MatchScope
}

func (s *spyStore) ReplaceMatches(ctx context.Context, scope store.MatchScope, ms []model.Match) ([]string, error) {
	s.replaced = append(s.replaced, scope)
	return s.Store.ReplaceMatches(ctx, scope, ms)
}

func (s *spyStore) replacedFor(src model.MatchSource) []store.MatchScope {
	var out []store.MatchScope
	for _, sc := range s.replaced {
		if sc.Source == src {
			out = append(out, sc)
		}
	}
	return out
}

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

// fakeMatcher answers MatchImage through fn; a nil fn matches nothing.
type fakeMatcher struct {
	src       model.MatchSource
	fn        func(in match.ImageInput) ([]model.Match, error)
	calls     int
	lastInput match.ImageInput
}

func (m *fakeMatcher) Source() model.MatchSource { return m.src }

func (m *fakeMatcher) MatchImage(_ context.Context, in match.ImageInput) ([]model.Match, error) {
	m.calls++
	m.lastInput = in
	if m.fn == nil {
		return nil, nil
	}
	return m.fn(in)
}

type fakeExceptions struct{ rules []findings.ExceptionRule }

func (f *fakeExceptions) ExceptionRules(context.Context) ([]findings.ExceptionRule, error) {
	return f.rules, nil
}

type fakeRecords struct {
	deltas []match.Delta
	calls  [][]osv.Changed
}

func (f *fakeRecords) ApplyOSV(_ context.Context, recs []osv.Changed) ([]match.Delta, error) {
	f.calls = append(f.calls, recs)
	return f.deltas, nil
}

// fakeGrype is the grype matcher: MatchImage through fakeMatcher, Rematch and RematchAll return
// delta. With notReady every call returns match.ErrNotReady.
type fakeGrype struct {
	fakeMatcher
	delta           match.Delta
	loaded          []string
	loadedBuilt     []time.Time
	rematchArgs     [][]grypedb.PackageKey
	rematchAllCalls int
	notReady        bool
}

func (g *fakeGrype) MatchImage(ctx context.Context, in match.ImageInput) ([]model.Match, error) {
	if g.notReady {
		g.calls++
		g.lastInput = in
		return nil, match.ErrNotReady
	}
	return g.fakeMatcher.MatchImage(ctx, in)
}

func (g *fakeGrype) Load(path string, built time.Time) error {
	g.loaded = append(g.loaded, path)
	g.loadedBuilt = append(g.loadedBuilt, built)
	return nil
}

func (g *fakeGrype) Rematch(_ context.Context, changed []grypedb.PackageKey) (match.Delta, error) {
	g.rematchArgs = append(g.rematchArgs, changed)
	if g.notReady {
		return match.Delta{}, match.ErrNotReady
	}
	return g.delta, nil
}

func (g *fakeGrype) RematchAll(context.Context) (match.Delta, error) {
	g.rematchAllCalls++
	if g.notReady {
		return match.Delta{}, match.ErrNotReady
	}
	return g.delta, nil
}

type harness struct {
	t          *testing.T
	st         *spyStore
	e          *engine.Engine
	clock      *clock
	osv        *fakeMatcher
	grype      *fakeGrype
	records    *fakeRecords
	exceptions *fakeExceptions
	libssl3    model.Package
	zlib1g     model.Package
}

// newHarness seeds a real store: catalogued images d1 (libssl3) and d2 (zlib1g), owners web/api on
// d1 and shop/cart on d2, and advisory CVE-2026-41873 rated critical by its CNA. The clock is t0.
func newHarness(t *testing.T) *harness {
	t.Helper()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "ffs.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })

	h := &harness{
		t:          t,
		st:         &spyStore{Store: st},
		clock:      &clock{now: t0},
		osv:        &fakeMatcher{src: model.SourceOSV},
		grype:      &fakeGrype{fakeMatcher: fakeMatcher{src: model.SourceGrype}},
		records:    &fakeRecords{},
		exceptions: &fakeExceptions{},
	}
	h.libssl3 = model.Package{ImageDigest: d1, Ecosystem: "deb", Distro: debian, Name: "libssl3", SourceName: "openssl", Version: "3.0.13-1", Arch: "amd64"}
	h.libssl3.ID = model.PackageID(d1, h.libssl3)
	h.zlib1g = model.Package{ImageDigest: d2, Ecosystem: "deb", Distro: debian, Name: "zlib1g", SourceName: "zlib", Version: "1:1.2.13.dfsg-1", Arch: "amd64"}
	h.zlib1g.ID = model.PackageID(d2, h.zlib1g)

	for _, img := range []struct {
		digest, repo string
		pkg          model.Package
	}{{d1, apiRepo, h.libssl3}, {d2, cartRepo, h.zlib1g}} {
		require.NoError(t, st.UpsertImage(ctx, model.Image{Digest: img.digest, Repo: img.repo, Platform: "linux/amd64",
			Status: model.ImageCatalogued, Source: "registry", ConfigUser: "app", CataloguedAt: t0.Add(-time.Hour)}))
		require.NoError(t, st.PutSBOM(ctx, img.digest, []byte(`{"artifacts":[]}`), []model.Package{img.pkg}))
	}
	for _, o := range []struct {
		ref          model.OwnerRef
		repo, digest string
	}{{apiRef, apiRepo, d1}, {cartRef, cartRepo, d2}} {
		require.NoError(t, st.UpsertOwner(ctx, model.Owner{Ref: o.ref, ServiceAccount: "default", Arch: []string{"amd64"},
			Containers: []model.ContainerUse{{Name: o.ref.Name, Kind: model.ContainerRegular, ImageRef: o.repo + ":1.0",
				Repo: o.repo, Digest: o.digest, Platform: "linux/amd64"}}}))
	}
	require.NoError(t, st.UpsertAdvisory(ctx, model.Advisory{ID: cve, Title: "OpenSSL buffer overflow",
		Published: t0.Add(-48 * time.Hour), Observed: t0.Add(-24 * time.Hour), CNASeverity: model.SeverityCritical, CNASource: "openssl"}))

	cfg := config.Default()
	cfg.ClusterName = "prod"
	h.e = engine.New(engine.Options{
		Config:     cfg,
		Store:      h.st,
		Exceptions: h.exceptions,
		Grype:      h.grype,
		Matchers:   []match.Matcher{h.osv},
		Records:    []match.RecordMatcher{h.records},
		Now:        h.clock.Now,
	})
	return h
}

// newMatch returns a fixed match of pkg on advisory from src.
func newMatch(pkg model.Package, advisory string, src model.MatchSource, fixed ...string) model.Match {
	return model.Match{ImageDigest: pkg.ImageDigest, PackageID: pkg.ID, AdvisoryID: advisory, Source: src,
		FixState: model.FixFixed, FixedVersions: fixed}
}

// grypeOn returns the grype match of the first test: CVE-2026-41873 on pkg, rated critical by
// Debian, from a DB built an hour after t0 (after the OSV observation, so grype has an opinion).
func (h *harness) grypeOn(pkg model.Package) model.Match {
	m := newMatch(pkg, cve, model.SourceGrype, "3.0.15-1")
	m.VendorSeverity, m.VendorSeveritySource = model.SeverityCritical, "debian"
	m.Namespace = "debian:distro:debian:12"
	m.DBBuilt = t0.Add(time.Hour)
	return m
}

// matchOn makes fn answer with ms for digest, and nothing for any other digest.
func matchOn(fn func(match.ImageInput) ([]model.Match, error), digest string, ms ...model.Match) func(match.ImageInput) ([]model.Match, error) {
	return func(in match.ImageInput) ([]model.Match, error) {
		if in.Digest == digest {
			return ms, nil
		}
		if fn != nil {
			return fn(in)
		}
		return nil, nil
	}
}

// catalogueAPI catalogues d1 with a grype and an OSV match on CVE-2026-41873 and drains, at t0.
func (h *harness) catalogueAPI() {
	h.t.Helper()
	h.grype.fn = matchOn(h.grype.fn, d1, h.grypeOn(h.libssl3))
	h.osv.fn = matchOn(h.osv.fn, d1, newMatch(h.libssl3, cve, model.SourceOSV, "3.0.15-1"))
	require.NoError(h.t, h.e.OnImageCatalogued(ctx, d1))
	require.NoError(h.t, h.e.Drain(ctx))
}

// catalogueBoth catalogues d1 as catalogueAPI does, and d2 with a grype match on zlib1g, at t0.
func (h *harness) catalogueBoth() {
	h.t.Helper()
	h.grype.fn = matchOn(h.grype.fn, d2, h.grypeOn(h.zlib1g))
	require.NoError(h.t, h.e.OnImageCatalogued(ctx, d2))
	h.catalogueAPI()
}

func (h *harness) findings(key string) []model.Finding {
	h.t.Helper()
	fs, err := h.st.FindingsForOwner(ctx, key)
	require.NoError(h.t, err)
	return fs
}

func (h *harness) finding(key, advisory string) model.Finding {
	h.t.Helper()
	for _, f := range h.findings(key) {
		if f.AdvisoryID == advisory {
			return f
		}
	}
	h.t.Fatalf("no %s finding for %s", advisory, key)
	return model.Finding{}
}

func (h *harness) transitions() []model.Transition {
	h.t.Helper()
	ts, err := h.st.TransitionsAfter(ctx, 0, 1000)
	require.NoError(h.t, err)
	return ts
}

func TestEngine_CataloguedImageProducesFindings(t *testing.T) {
	h := newHarness(t)
	ch := h.e.Changed()
	other := h.e.Changed()
	h.catalogueAPI()

	fs := h.findings(apiKey)
	require.Len(t, fs, 1)
	f := fs[0]
	require.Equal(t, model.StateOpen, f.State)
	require.Equal(t, model.PriorityHigh, f.Priority)
	require.GreaterOrEqual(t, len(f.Reasons), 2)
	require.Equal(t, []string{"critical severity", "fix available: 3.0.15-1"}, f.Reasons[:2])
	require.False(t, f.Provisional, "grype has an opinion from a DB built after the OSV observation")
	require.Equal(t, model.FindingFingerprint("prod", apiRef, apiRepo, cve), f.Fingerprint)
	require.Equal(t, t0, f.Matched)

	ts := h.transitions()
	require.Len(t, ts, 1)
	require.Equal(t, model.FindingState(""), ts[0].FromState)
	require.Equal(t, model.StateOpen, ts[0].ToState)
	require.Equal(t, model.TriggerInventoryChange, ts[0].Trigger)
	require.Empty(t, h.findings(cartKey), "only the owners of d1 are recomputed")

	for _, c := range []<-chan struct{}{ch, other} {
		select {
		case <-c:
		default:
			t.Fatal("every Changed subscriber is signalled")
		}
	}

	osvMatch := newMatch(h.libssl3, cve, model.SourceOSV, "3.0.15-1")
	osvMatch.ObservedAt = t0
	require.Equal(t, []model.Match{osvMatch}, h.grype.lastInput.Hints, "grype gets this run's OSV matches as hints")
	require.Equal(t, 1, h.osv.calls)
	require.Len(t, h.st.replacedFor(model.SourceOSV), 1)
	require.Equal(t, []store.MatchScope{{Source: model.SourceGrype, Digests: []string{d1}}}, h.st.replacedFor(model.SourceGrype))
}

func TestEngine_OSVDeltaRecomputesOnlyAffectedOwners(t *testing.T) {
	h := newHarness(t)
	h.catalogueBoth()
	require.NotEmpty(t, h.findings(cartKey))
	t1 := t0.Add(time.Hour)
	h.clock.now = t1

	const newCVE = "CVE-2026-50001"
	h.records.deltas = []match.Delta{{
		Scope:   store.MatchScope{Source: model.SourceOSV, AdvisoryIDs: []string{newCVE}},
		Matches: []model.Match{newMatch(h.libssl3, newCVE, model.SourceOSV, "3.0.16-1")},
	}}
	recs := []osv.Changed{{Ecosystem: "Debian", ID: "DSA-6001-1"}}
	require.NoError(t, h.e.OnOSVRecords(ctx, recs))
	require.Equal(t, [][]osv.Changed{recs}, h.records.calls)
	require.NoError(t, h.e.Drain(ctx))

	f := h.finding(apiKey, newCVE)
	require.Equal(t, model.StateOpen, f.State)
	require.True(t, f.Provisional, "an OSV-only finding waits for two grype DBs")
	require.Equal(t, t1, f.Matched)

	var sawNew bool
	for _, tr := range h.transitions() {
		if tr.AdvisoryID == newCVE {
			sawNew = true
			require.Equal(t, model.TriggerNewAdvisory, tr.Trigger)
			require.True(t, tr.Provisional)
		}
		if tr.Owner.Key() == cartKey {
			require.Equal(t, t0, tr.At, "shop/cart has no transition after t0")
		}
	}
	require.True(t, sawNew)
	for _, f := range h.findings(cartKey) {
		require.Equal(t, t0, f.LastSeen, "shop/cart was not recomputed")
	}
	require.Equal(t, t1, h.finding(apiKey, cve).LastSeen, "web/api was recomputed")
}

func TestEngine_KEVEnrichmentEscalates(t *testing.T) {
	h := newHarness(t)
	h.catalogueAPI()
	require.Equal(t, model.PriorityHigh, h.finding(apiKey, cve).Priority)

	added := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	require.NoError(t, h.st.UpsertAdvisory(ctx, model.Advisory{ID: cve, KEVAdded: &added}))
	require.NoError(t, h.e.OnAdvisoriesEnriched(ctx, []string{cve}))
	require.NoError(t, h.e.Drain(ctx))

	ts := h.transitions()
	last := ts[len(ts)-1]
	require.Equal(t, model.StateOpen, last.FromState)
	require.Equal(t, model.StateOpen, last.ToState)
	require.Equal(t, model.PriorityHigh, last.FromPriority)
	require.Equal(t, model.PriorityUrgent, last.ToPriority)
	require.Equal(t, model.TriggerPriorityChange, last.Trigger)
	require.Equal(t, "actively exploited (CISA KEV, added 2026-11-02)", h.finding(apiKey, cve).Reasons[0])
}

func TestEngine_ExceptionExpiryReopens(t *testing.T) {
	h := newHarness(t)
	h.catalogueAPI()

	h.exceptions.rules = []findings.ExceptionRule{{Namespace: "web", Name: "accept", AdvisoryIDs: []string{cve},
		Expires: t0.Add(30 * time.Second)}}
	require.NoError(t, h.e.OnExceptionsChanged(ctx))
	require.NoError(t, h.e.Drain(ctx))
	f := h.finding(apiKey, cve)
	require.Equal(t, model.StateExcepted, f.State)
	require.Equal(t, "web/accept", f.ExceptedBy)

	h.clock.now = t0.Add(20 * time.Second)
	require.NoError(t, h.e.CheckExceptionExpiry(ctx))
	require.True(t, h.e.Idle(), "nothing has expired yet")

	h.clock.now = t0.Add(61 * time.Second)
	require.NoError(t, h.e.CheckExceptionExpiry(ctx))
	require.NoError(t, h.e.Drain(ctx))
	ts := h.transitions()
	last := ts[len(ts)-1]
	require.Equal(t, model.StateExcepted, last.FromState)
	require.Equal(t, model.StateOpen, last.ToState)
	require.Equal(t, model.TriggerExceptionExpired, last.Trigger)
	require.Equal(t, model.StateOpen, h.finding(apiKey, cve).State)

	n := len(ts)
	require.NoError(t, h.e.CheckExceptionExpiry(ctx))
	require.True(t, h.e.Idle(), "an expiry is acted on once")
	require.Len(t, h.transitions(), n)
}

func TestEngine_MatcherErrorKeepsExistingMatches(t *testing.T) {
	h := newHarness(t)
	h.catalogueAPI()
	t1 := t0.Add(time.Hour)
	h.clock.now = t1

	boom := errors.New("grype exploded")
	h.grype.fn = func(match.ImageInput) ([]model.Match, error) { return nil, boom }
	err := h.e.OnImageCatalogued(ctx, d1)
	require.ErrorIs(t, err, boom)

	ms, err := h.st.MatchesForDigests(ctx, []string{d1})
	require.NoError(t, err)
	var grypeMatches []model.Match
	for _, m := range ms {
		if m.Source == model.SourceGrype {
			grypeMatches = append(grypeMatches, m)
		}
	}
	require.Len(t, grypeMatches, 1, "a failed matcher leaves its stored matches")
	require.Equal(t, cve, grypeMatches[0].AdvisoryID)
	require.Len(t, h.st.replacedFor(model.SourceGrype), 1, "only the first, successful run replaced grype matches")

	require.False(t, h.e.Idle(), "the owners of d1 are queued despite the error")
	require.NoError(t, h.e.Drain(ctx))
	require.Equal(t, t1, h.finding(apiKey, cve).LastSeen)
}

func TestEngine_GrypeNotReadyStillRecomputes(t *testing.T) {
	h := newHarness(t)
	const stale = "CVE-2026-0002"
	stored := newMatch(h.libssl3, stale, model.SourceGrype, "3.0.14-1")
	_, err := h.st.Store.ReplaceMatches(ctx, store.MatchScope{Source: model.SourceGrype, Digests: []string{d1}}, []model.Match{stored})
	require.NoError(t, err)

	h.grype.notReady = true
	h.osv.fn = matchOn(nil, d1, newMatch(h.libssl3, cve, model.SourceOSV, "3.0.15-1"))
	require.NoError(t, h.e.OnImageCatalogued(ctx, d1))
	require.NoError(t, h.e.Drain(ctx))

	f := h.finding(apiKey, cve)
	require.Equal(t, model.StateOpen, f.State)
	require.True(t, f.Provisional)
	require.Empty(t, h.st.replacedFor(model.SourceGrype), "no grype opinion, so no grype ReplaceMatches")
	ms, err := h.st.MatchesForDigests(ctx, []string{d1})
	require.NoError(t, err)
	require.Contains(t, advisories(ms, model.SourceGrype), stale, "stored grype matches are untouched")

	got, err := h.e.MatchCandidate(ctx, d1)
	require.NoError(t, err)
	require.Equal(t, []string{cve}, advisories(got, model.SourceOSV))
	require.Empty(t, advisories(got, model.SourceGrype))
}

func advisories(ms []model.Match, src model.MatchSource) []string {
	var out []string
	for _, m := range ms {
		if m.Source == src {
			out = append(out, m.AdvisoryID)
		}
	}
	return out
}

func TestEngine_ObservedAtPreservedAcrossRematch(t *testing.T) {
	h := newHarness(t)
	h.osv.fn = func(in match.ImageInput) ([]model.Match, error) {
		m := newMatch(h.libssl3, cve, model.SourceOSV, "3.0.15-1")
		m.ObservedAt = h.clock.now
		return []model.Match{m}, nil
	}
	require.NoError(t, h.e.OnImageCatalogued(ctx, d1))

	h.clock.now = t0.Add(time.Hour)
	require.NoError(t, h.e.OnImageCatalogued(ctx, d1))
	require.Len(t, h.grype.lastInput.Hints, 1)
	require.Equal(t, t0, h.grype.lastInput.Hints[0].ObservedAt, "the in-memory match takes the stored ObservedAt")
	ms, err := h.st.MatchesForDigests(ctx, []string{d1})
	require.NoError(t, err)
	require.Len(t, ms, 1)
	require.Equal(t, t0, ms[0].ObservedAt)

	// a delta that re-delivers the match keeps it too, and a new match is observed now
	h.clock.now = t0.Add(2 * time.Hour)
	again := newMatch(h.libssl3, cve, model.SourceOSV, "3.0.15-1")
	fresh := newMatch(h.libssl3, "CVE-2026-0003", model.SourceOSV)
	require.NoError(t, h.e.OnMatchDelta(ctx, match.Delta{
		Scope:   store.MatchScope{Source: model.SourceOSV, Digests: []string{d1}},
		Matches: []model.Match{again, fresh},
	}, model.TriggerNewAdvisory))
	ms, err = h.st.MatchesForDigests(ctx, []string{d1})
	require.NoError(t, err)
	observed := map[string]time.Time{}
	for _, m := range ms {
		observed[m.AdvisoryID] = m.ObservedAt
	}
	require.Equal(t, map[string]time.Time{cve: t0, "CVE-2026-0003": t0.Add(2 * time.Hour)}, observed)
}

func TestEngine_GrypeDBRecordsBuildAndRematchesAffected(t *testing.T) {
	h := newHarness(t)
	h.catalogueBoth()
	t1 := t0.Add(2 * time.Hour)
	h.clock.now = t1
	b := t0.Add(90 * time.Minute)

	rematched := h.grypeOn(h.libssl3)
	rematched.DBBuilt = b
	h.grype.delta = match.Delta{Scope: store.MatchScope{Source: model.SourceGrype, Digests: []string{d1}}, Matches: []model.Match{rematched}}
	changed := []grypedb.PackageKey{{Ecosystem: "deb", Name: "libssl3"}}
	require.NoError(t, h.e.OnGrypeDB(ctx, grypedb.Update{Path: "/db/b", Built: b, Changed: changed}))

	require.Equal(t, []string{"/db/b"}, h.grype.loaded)
	require.Equal(t, []time.Time{b}, h.grype.loadedBuilt)
	builds, err := h.st.GrypeDBBuilds(ctx)
	require.NoError(t, err)
	require.Equal(t, []time.Time{b}, builds)
	require.Equal(t, [][]grypedb.PackageKey{changed}, h.grype.rematchArgs)
	require.Zero(t, h.grype.rematchAllCalls)

	ms, err := h.st.MatchesForDigests(ctx, []string{d1})
	require.NoError(t, err)
	for _, m := range ms {
		if m.Source == model.SourceGrype {
			require.Equal(t, b, m.DBBuilt, "the delta replaced d1's grype matches")
		}
	}

	require.False(t, h.e.Idle())
	require.NoError(t, h.e.Drain(ctx))
	for _, f := range h.findings(cartKey) {
		require.Equal(t, t1, f.LastSeen, "every owner is recomputed, shop/cart included")
	}
}

func TestEngine_GrypeDBLoadFailureRecordsNothing(t *testing.T) {
	h := newHarness(t)
	failing := &failingLoad{fakeGrype: h.grype}
	e := engine.New(engine.Options{Config: config.Default(), Store: h.st, Grype: failing, Now: h.clock.Now})
	require.Error(t, e.OnGrypeDB(ctx, grypedb.Update{Path: "/db/x", Built: t0, Full: true}))
	builds, err := h.st.GrypeDBBuilds(ctx)
	require.NoError(t, err)
	require.Empty(t, builds, "the build is recorded only once it loaded")
	require.Zero(t, h.grype.rematchAllCalls)
	require.True(t, e.Idle())
}

type failingLoad struct{ *fakeGrype }

func (f *failingLoad) Load(string, time.Time) error { return errors.New("corrupt database") }

func TestEngine_GrypeDBFullUsesRematchAll(t *testing.T) {
	h := newHarness(t)
	h.grype.delta = match.Delta{Scope: store.MatchScope{Source: model.SourceGrype}}
	require.NoError(t, h.e.OnGrypeDB(ctx, grypedb.Update{Path: "/db/c", Built: t0, Full: true}))
	require.Equal(t, 1, h.grype.rematchAllCalls)
	require.Empty(t, h.grype.rematchArgs)
	require.Empty(t, h.st.replaced, "a delta with an empty scope replaces nothing")
}

func TestEngine_AliasRekeyNoTransition(t *testing.T) {
	h := newHarness(t)
	const ghsa, alias = "GHSA-aaaa-bbbb-cccc", "CVE-2026-0001"
	require.NoError(t, h.st.UpsertAdvisory(ctx, model.Advisory{ID: ghsa, Title: "libssl3 flaw"}))
	_, err := h.st.Store.ReplaceMatches(ctx, store.MatchScope{Source: model.SourceOSV, Digests: []string{d1}},
		[]model.Match{newMatch(h.libssl3, ghsa, model.SourceOSV, "3.0.15-1")})
	require.NoError(t, err)
	require.NoError(t, h.e.OnOwnersChanged(ctx, []string{apiKey}))
	require.NoError(t, h.e.Drain(ctx))
	require.Equal(t, model.StateOpen, h.finding(apiKey, ghsa).State)
	require.Len(t, h.transitions(), 1)

	h.clock.now = t0.Add(time.Hour)
	require.NoError(t, h.st.UpsertAdvisory(ctx, model.Advisory{ID: ghsa, Aliases: []string{alias}}))
	require.NoError(t, h.e.OnAdvisoriesEnriched(ctx, []string{alias}))
	require.NoError(t, h.e.Drain(ctx))

	require.Len(t, h.transitions(), 1, "an alias merge emits no transition")
	fs := h.findings(apiKey)
	require.Len(t, fs, 1)
	require.Equal(t, alias, fs[0].AdvisoryID)
	require.Equal(t, model.FindingFingerprint("prod", apiRef, apiRepo, alias), fs[0].Fingerprint)
	require.Equal(t, t0, fs[0].Matched)
	require.Equal(t, t0.Add(time.Hour), fs[0].LastSeen)
}

func TestEngine_IdleAfterDrain(t *testing.T) {
	h := newHarness(t)
	require.True(t, h.e.Idle())
	require.NoError(t, h.e.OnOwnersChanged(ctx, []string{apiKey}))
	require.False(t, h.e.Idle())
	require.NoError(t, h.e.Drain(ctx))
	require.True(t, h.e.Idle())
}

func TestEngine_PruneUsesRetention(t *testing.T) {
	h := newHarness(t)
	resolved := func(advisory string, at time.Time) model.Finding {
		return model.Finding{Fingerprint: model.FindingFingerprint("prod", apiRef, apiRepo, advisory), Owner: apiRef,
			ImageRepo: apiRepo, AdvisoryID: advisory, State: model.StateResolved, ResolvedAt: &at, Matched: t0.AddDate(0, -4, 0)}
	}
	older := resolved("CVE-2026-1000", t0.Add(-2161*time.Hour))
	newer := resolved("CVE-2026-1001", t0.Add(-2159*time.Hour))
	require.NoError(t, h.st.ApplyFindings(ctx, []model.Finding{older, newer}, nil))

	n, err := h.e.Prune(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	fs := h.findings(apiKey)
	require.Len(t, fs, 1)
	require.Equal(t, newer.Fingerprint, fs[0].Fingerprint)
}

func TestEngine_StartDrainsOnWake(t *testing.T) {
	h := newHarness(t)
	h.osv.fn = matchOn(nil, d1, newMatch(h.libssl3, cve, model.SourceOSV, "3.0.15-1"))
	ch := h.e.Changed()

	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- h.e.Start(runCtx) }()
	require.NoError(t, h.e.OnImageCatalogued(ctx, d1))
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatal("Start did not drain the queued owner")
	}
	require.Eventually(t, h.e.Idle, 10*time.Second, 10*time.Millisecond)
	cancel()
	require.NoError(t, <-done)
	require.True(t, h.e.Idle())
	require.Len(t, h.findings(apiKey), 1)
}

// TestEngine_StartCatchesUp is the F6 regression: matches stored before a restart, whose owners were
// queued only in the previous process's memory, produce findings once Start runs, with no hook.
func TestEngine_StartCatchesUp(t *testing.T) {
	h := newHarness(t)
	_, err := h.st.Store.ReplaceMatches(ctx, store.MatchScope{Source: model.SourceGrype, Digests: []string{d1}},
		[]model.Match{h.grypeOn(h.libssl3)})
	require.NoError(t, err)
	ch := h.e.Changed()

	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- h.e.Start(runCtx) }()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not recompute the owners queued before the restart")
	}
	require.Eventually(t, h.e.Idle, 10*time.Second, 10*time.Millisecond)
	cancel()
	require.NoError(t, <-done)
	require.Equal(t, model.StateOpen, h.finding(apiKey, cve).State)
	require.Equal(t, model.TriggerInventoryChange, h.transitions()[0].Trigger)
}

// TestEngine_GrypeOpinionStandsOnNewDigest is the F2 regression. The OSV record was observed three
// days ago and the loaded grype DB was built a day ago, so grype has an opinion (spec §6.5). An image
// catalogued now, a new digest after a rollout, must keep grype's verdict (won't fix, low) instead of
// letting the OSV verdict stand as urgent and provisional because its match rows are new.
func TestEngine_GrypeOpinionStandsOnNewDigest(t *testing.T) {
	h := newHarness(t)
	const cve5535 = "CVE-2024-5535"
	raw, err := os.ReadFile(filepath.Join("..", "match", "osvfast", "testdata", "DEBIAN-CVE-2024-5535.json"))
	require.NoError(t, err)
	v, err := match.ParseOSV(raw)
	require.NoError(t, err)
	hash, err := osv.AffectedHash(raw)
	require.NoError(t, err)
	_, err = h.st.PutOSVRecordAt(ctx, "Debian", v.GetId(), v.GetModified().AsTime(), hash, raw, t0.Add(-72*time.Hour))
	require.NoError(t, err)
	require.NoError(t, h.st.PutOSVRecordNames(ctx, "Debian", v.GetId(), []string{osv.IndexName("Debian", "openssl")}))
	canon, err := match.UpsertOSVAdvisory(ctx, h.st.Store, v)
	require.NoError(t, err)
	require.Equal(t, cve5535, canon)
	require.NoError(t, h.st.UpsertAdvisory(ctx, model.Advisory{ID: cve5535, CNASeverity: model.SeverityCritical, CNASource: "openssl"}))
	built := t0.Add(-24 * time.Hour)
	require.NoError(t, h.st.RecordGrypeDBBuild(ctx, built))

	o, _, err := h.st.GetOwner(ctx, apiKey)
	require.NoError(t, err)
	o.Context = model.WorkloadContext{Exposed: true, ExposurePaths: []string{"Ingress web/api"}}
	require.NoError(t, h.st.UpsertOwner(ctx, o))
	wontFix := model.Match{ImageDigest: d1, PackageID: h.libssl3.ID, AdvisoryID: cve5535, Source: model.SourceGrype,
		FixState: model.FixWontFix, VendorSeverity: model.SeverityLow, VendorSeveritySource: "debian",
		Namespace: "debian:distro:debian:12", DBBuilt: built}
	h.grype.fn = matchOn(nil, d1, wontFix)
	e := engine.New(engine.Options{Config: config.Default(), Store: h.st, Grype: h.grype,
		Matchers: []match.Matcher{osvfast.New(h.st.Store)}, Now: h.clock.Now})

	require.NoError(t, e.OnImageCatalogued(ctx, d1))
	require.NoError(t, e.Drain(ctx))
	f := h.finding(apiKey, cve5535)
	require.False(t, f.Provisional, "grype's DB was built after ffs observed the OSV record")
	require.Equal(t, model.FixWontFix, f.FixState)
	require.Equal(t, model.PriorityLow, f.Priority)
	require.Equal(t, "debian", f.SeveritySource)

	osvMatches := advisories(h.grype.lastInput.Hints, model.SourceOSV)
	require.Equal(t, []string{cve5535}, osvMatches, "the OSV fast path matched the new digest")
	require.Equal(t, t0.Add(-72*time.Hour), h.grype.lastInput.Hints[0].ObservedAt)
	got, err := e.MatchCandidate(ctx, d1)
	require.NoError(t, err)
	for _, m := range got {
		if m.Source == model.SourceOSV {
			require.Equal(t, t0.Add(-72*time.Hour), m.ObservedAt, "candidates are scored with the same observation")
		}
	}
}

// TestEngine_RolloutToUncataloguedDigestKeepsFindings is the F3 regression: while the digest an owner
// rolled out to is pending or unresolvable its findings stand, with no transition, and they resolve
// as an inventory change only once the new digest is catalogued without them.
func TestEngine_RolloutToUncataloguedDigestKeepsFindings(t *testing.T) {
	h := newHarness(t)
	h.catalogueAPI()
	require.Equal(t, model.StateOpen, h.finding(apiKey, cve).State)
	n := len(h.transitions())

	const d3 = "sha256:d3"
	rollout := func(status model.ImageStatus) {
		t.Helper()
		require.NoError(t, h.st.UpsertImage(ctx, model.Image{Digest: d3, Repo: apiRepo, Platform: "linux/amd64", Status: status}))
		o, _, err := h.st.GetOwner(ctx, apiKey)
		require.NoError(t, err)
		o.Containers[0].Digest = d3
		require.NoError(t, h.st.UpsertOwner(ctx, o))
		require.NoError(t, h.e.OnOwnersChanged(ctx, []string{apiKey}))
		require.NoError(t, h.e.Drain(ctx))
	}
	h.clock.now = t0.Add(time.Hour)
	rollout(model.ImagePending)
	f := h.finding(apiKey, cve)
	require.Equal(t, model.StateOpen, f.State, "a pending digest is not clean")
	require.Equal(t, model.PriorityHigh, f.Priority)
	require.Len(t, h.transitions(), n, "no resolution while the new digest is unknown")

	h.clock.now = t0.Add(2 * time.Hour)
	rollout(model.ImageUnresolvable)
	require.Equal(t, model.StateOpen, h.finding(apiKey, cve).State, "an unresolvable digest is never clean")
	require.Len(t, h.transitions(), n)

	// d3 is catalogued with the fixed libssl3: the finding resolves as an inventory change
	h.clock.now = t0.Add(3 * time.Hour)
	fixed := h.libssl3
	fixed.ImageDigest, fixed.Version = d3, "3.0.15-1"
	fixed.ID = model.PackageID(d3, fixed)
	require.NoError(t, h.st.PutSBOM(ctx, d3, []byte(`{"artifacts":[]}`), []model.Package{fixed}))
	require.NoError(t, h.st.UpsertImage(ctx, model.Image{Digest: d3, Repo: apiRepo, Platform: "linux/amd64",
		Status: model.ImageCatalogued, CataloguedAt: h.clock.now}))
	require.NoError(t, h.e.OnImageCatalogued(ctx, d3))
	require.NoError(t, h.e.Drain(ctx))
	require.Equal(t, model.StateResolved, h.finding(apiKey, cve).State)
	ts := h.transitions()
	require.Len(t, ts, n+1)
	require.Equal(t, model.TriggerInventoryChange, ts[n].Trigger)
}

// TestEngine_ProvisionalResolutionTrigger is the F29 regression: a provisional finding resolves as
// withdrawn only when the advisory went away for the image the owner still runs (a feed change, or
// grype's not-affected verdict), never when the team shipped the fix.
func TestEngine_ProvisionalResolutionTrigger(t *testing.T) {
	provisional := func(t *testing.T) *harness {
		t.Helper()
		h := newHarness(t)
		h.osv.fn = matchOn(nil, d1, newMatch(h.libssl3, cve, model.SourceOSV, "3.0.15-1"))
		require.NoError(t, h.e.OnImageCatalogued(ctx, d1))
		require.NoError(t, h.e.Drain(ctx))
		require.True(t, h.finding(apiKey, cve).Provisional)
		h.clock.now = t0.Add(time.Hour)
		return h
	}
	lastTrigger := func(h *harness) model.Trigger {
		ts := h.transitions()
		require.Equal(h.t, model.StateResolved, ts[len(ts)-1].ToState)
		return ts[len(ts)-1].Trigger
	}

	t.Run("the team shipped the fix", func(t *testing.T) {
		h := provisional(t)
		const d4 = "sha256:d4"
		fixed := h.libssl3
		fixed.ImageDigest, fixed.Version = d4, "3.0.15-1"
		fixed.ID = model.PackageID(d4, fixed)
		require.NoError(t, h.st.UpsertImage(ctx, model.Image{Digest: d4, Repo: apiRepo, Platform: "linux/amd64",
			Status: model.ImageCatalogued, CataloguedAt: h.clock.now}))
		require.NoError(t, h.st.PutSBOM(ctx, d4, []byte(`{"artifacts":[]}`), []model.Package{fixed}))
		require.NoError(t, h.e.OnImageCatalogued(ctx, d4))
		o, _, err := h.st.GetOwner(ctx, apiKey)
		require.NoError(t, err)
		o.Containers[0].Digest = d4
		require.NoError(t, h.st.UpsertOwner(ctx, o))
		require.NoError(t, h.e.OnOwnersChanged(ctx, []string{apiKey}))
		require.NoError(t, h.e.Drain(ctx))
		require.Equal(t, model.TriggerInventoryChange, lastTrigger(h))
	})

	t.Run("the OSV record was withdrawn", func(t *testing.T) {
		h := provisional(t)
		require.NoError(t, h.e.OnMatchDelta(ctx, match.Delta{
			Scope: store.MatchScope{Source: model.SourceOSV, AdvisoryIDs: []string{cve}}}, model.TriggerNewAdvisory))
		require.NoError(t, h.e.Drain(ctx))
		require.Equal(t, model.TriggerWithdrawn, lastTrigger(h))
	})

	t.Run("grype says not affected", func(t *testing.T) {
		h := provisional(t)
		na := newMatch(h.libssl3, cve, model.SourceGrype)
		na.FixState, na.DBBuilt = model.FixNotAffected, t0.Add(30*time.Minute)
		h.grype.fn = matchOn(nil, d1, na)
		require.NoError(t, h.e.OnImageCatalogued(ctx, d1))
		require.NoError(t, h.e.Drain(ctx))
		require.Equal(t, model.TriggerWithdrawn, lastTrigger(h), "even on an inventory-change recompute")
	})
}
