package upgrade

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/eol"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/registry"
	"github.com/the-it-dept/ffs/internal/sbom"
	"github.com/the-it-dept/ffs/internal/store"
)

const (
	webKey   = "Deployment/shop/web"
	nginx    = "docker.io/library/nginx"
	curAMD64 = "sha256:cur-amd64"
	curIdx   = "sha256:cur-idx"
	advA     = "CVE-2026-1001"
	advB     = "CVE-2026-1002"
)

var (
	rctx   = context.Background()
	rnow   = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	webRef = model.OwnerRef{Kind: "Deployment", Namespace: "shop", Name: "web", UID: "uid-web"}
)

// fakeRegistry lists tags, resolves tags from a map (unknown tags are not found) and resolves an
// index "<x>-idx" to the platform manifest "<x>-<arch>".
type fakeRegistry struct {
	tags      []string
	listErr   error // ListTags fails with it when set
	resolve   map[string]string
	platforms []string // PlatformManifest platforms, in call order
}

func (f *fakeRegistry) ListTags(context.Context, string, registry.CredSet) ([]string, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.tags, nil
}

func (f *fakeRegistry) ResolveTag(_ context.Context, _, tag string, _ registry.CredSet) (string, error) {
	d, ok := f.resolve[tag]
	if !ok {
		return "", registry.ErrNotFound
	}
	return d, nil
}

func (f *fakeRegistry) PlatformManifest(_ context.Context, _, digest, platform string, _ registry.CredSet) (registry.Manifest, error) {
	f.platforms = append(f.platforms, platform)
	arch := strings.TrimPrefix(platform, "linux/")
	return registry.Manifest{Digest: strings.TrimSuffix(digest, "-idx") + "-" + arch, IndexDigest: digest, Platform: platform}, nil
}

// fakeAcquirer records requests and fails the digests in errs.
type fakeAcquirer struct {
	reqs []sbom.Request
	errs map[string]error
}

func (f *fakeAcquirer) AcquireNow(_ context.Context, r sbom.Request) (*sbom.Result, error) {
	f.reqs = append(f.reqs, r)
	if err := f.errs[r.Digest]; err != nil {
		return nil, err
	}
	return &sbom.Result{Source: "registry"}, nil
}

func (f *fakeAcquirer) digests() []string {
	var out []string
	for _, r := range f.reqs {
		out = append(out, r.Digest)
	}
	return out
}

// fakeScorer gives each candidate platform digest the findings in byDigest, or def when absent.
type fakeScorer struct {
	byDigest map[string][]model.Finding
	def      []model.Finding
}

func (f *fakeScorer) on(digest string) []model.Finding {
	if fs, ok := f.byDigest[digest]; ok {
		return fs
	}
	return f.def
}

func (f *fakeScorer) MatchCandidate(_ context.Context, digest string) ([]model.Match, error) {
	var ms []model.Match
	for _, c := range f.on(digest) {
		ms = append(ms, model.Match{ImageDigest: digest, AdvisoryID: c.AdvisoryID})
	}
	return ms, nil
}

func (f *fakeScorer) ScoreMatches(_ context.Context, owner model.Owner, repo string, ms []model.Match) ([]model.Finding, error) {
	byID := map[string]model.Finding{}
	var order []string
	for _, m := range ms {
		for _, c := range f.on(m.ImageDigest) {
			if c.AdvisoryID != m.AdvisoryID {
				continue
			}
			got, seen := byID[c.AdvisoryID]
			if !seen {
				order = append(order, c.AdvisoryID)
				got = c
				got.Owner, got.ImageRepo = owner.Ref, repo
			}
			got.Digests = append(got.Digests, m.ImageDigest)
			byID[c.AdvisoryID] = got
		}
	}
	var out []model.Finding
	for _, id := range order {
		out = append(out, byID[id])
	}
	return out, nil
}

// cf is a fixable open finding on a candidate.
func cf(id string, p model.Priority) model.Finding {
	return model.Finding{AdvisoryID: id, State: model.StateOpen, Priority: p, FixAvailable: true}
}

type rig struct {
	t   *testing.T
	st  *store.Store
	reg *fakeRegistry
	acq *fakeAcquirer
	sc  *fakeScorer
	now time.Time
	r   *Resolver
}

// newRig seeds a real store with the owner Deployment/shop/web running nginx:1.30.6 (sha256:cur-amd64
// from the index sha256:cur-idx, debian 12) on amd64 with the pull secret regcred, and open fixable
// findings A (urgent) and B (high) on it. The registry lists the nginx tags testdata and resolves
// 1.30.6 to the refresh sha256:new-idx, 1.30.7 to sha256:c77-idx and 1.31.9 to sha256:c319-idx. Every
// candidate fixes everything unless the scorer is told otherwise.
func newRig(t *testing.T) *rig {
	t.Helper()
	st, err := store.Open(rctx, filepath.Join(t.TempDir(), "ffs.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	raw, err := os.ReadFile("testdata/tags/nginx.txt")
	require.NoError(t, err)

	rg := &rig{t: t, st: st, now: rnow, acq: &fakeAcquirer{}, sc: &fakeScorer{},
		reg: &fakeRegistry{tags: strings.Fields(string(raw)), resolve: map[string]string{
			"1.30.6": "sha256:new-idx", "1.30.7": "sha256:c77-idx", "1.31.9": "sha256:c319-idx", "2.0.0": "sha256:c200-idx",
		}}}
	rg.putImage(curAMD64, curIdx, "12")
	require.NoError(t, st.UpsertOwner(rctx, model.Owner{Ref: webRef, ServiceAccount: "web", PullSecrets: []string{"regcred"},
		Arch: []string{"amd64"}, Containers: []model.ContainerUse{{Name: "web", Kind: model.ContainerRegular,
			ImageRef: "nginx:1.30.6", Repo: nginx, Digest: curAMD64, Platform: "linux/amd64"}}}))
	require.NoError(t, st.ApplyFindings(rctx, []model.Finding{rg.finding(advA, model.PriorityUrgent, curAMD64),
		rg.finding(advB, model.PriorityHigh, curAMD64)}, nil))

	require.NoError(t, st.ReplaceEOL(rctx, []store.EOLCycle{
		{Product: "debian", Cycle: "11", EOLDate: day(2026, 8, 31)},
		{Product: "debian", Cycle: "12", EOLDate: day(2028, 6, 30)},
	}))
	ev := eol.New(st, func() time.Time { return rg.now })
	require.NoError(t, ev.Reload(rctx))
	p, err := NewParser(nil)
	require.NoError(t, err)
	rg.r = NewResolver(Options{Store: st, Registry: rg.reg, Acquirer: rg.acq, Scorer: rg.sc, EOL: ev, Parser: p,
		Config: config.Default(), Now: func() time.Time { return rg.now }})
	return rg
}

func day(y int, m time.Month, d int) *time.Time {
	t := time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
	return &t
}

// putImage stores a catalogued nginx image on debian release.
func (rg *rig) putImage(digest, index, release string) {
	rg.t.Helper()
	require.NoError(rg.t, rg.st.UpsertImage(rctx, model.Image{Digest: digest, IndexDigest: index, Repo: nginx,
		Platform: "linux/amd64", Status: model.ImageCatalogued, Source: "registry", CataloguedAt: rnow.Add(-time.Hour)}))
	require.NoError(rg.t, rg.st.PutSBOM(rctx, digest, []byte(`{"artifacts":[]}`), []model.Package{{Ecosystem: "deb",
		Distro: &model.Distro{ID: "debian", VersionID: release}, Name: "libssl3", Version: "3.0.13-1"}}))
}

// finding is an open fixable finding of the owner on nginx.
func (rg *rig) finding(id string, p model.Priority, digest string) model.Finding {
	return model.Finding{Fingerprint: model.FindingFingerprint("default", webRef, nginx, id), Owner: webRef,
		ImageRepo: nginx, AdvisoryID: id, Digests: []string{digest}, State: model.StateOpen, Priority: p,
		FixAvailable: true, Matched: rnow.Add(-time.Hour), LastSeen: rnow}
}

func (rg *rig) setOwner(fn func(o *model.Owner)) {
	rg.t.Helper()
	o, ok, err := rg.st.GetOwner(rctx, webKey)
	require.NoError(rg.t, err)
	require.True(rg.t, ok)
	fn(&o)
	require.NoError(rg.t, rg.st.UpsertOwner(rctx, o))
}

func (rg *rig) resolve() {
	rg.t.Helper()
	require.NoError(rg.t, rg.r.ResolveOwner(rctx, webKey))
}

func (rg *rig) suggestion() store.OwnerSuggestion {
	rg.t.Helper()
	got, ok, err := rg.st.GetSuggestion(rctx, webKey, nginx)
	require.NoError(rg.t, err)
	require.True(rg.t, ok, "a suggestion is stored")
	return got
}

func (rg *rig) upgradeTransitions() []model.Transition {
	rg.t.Helper()
	ts, err := rg.st.TransitionsAfter(rctx, 0, 1000)
	require.NoError(rg.t, err)
	var out []model.Transition
	for _, t := range ts {
		if t.Trigger == model.TriggerUpgradeAvailable {
			out = append(out, t)
		}
	}
	return out
}

func tags(cs []store.CandidateDigest) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.Tag)
	}
	return out
}

func TestResolver_RefreshRecommended(t *testing.T) {
	rg := newRig(t)
	rg.resolve()

	got := rg.suggestion()
	sg := got.Suggestion
	require.Equal(t, model.TierRefresh, sg.Tier)
	require.Equal(t, "1.30.6", sg.FromTag)
	require.Equal(t, "1.30.6", sg.ToTag)
	require.Equal(t, "sha256:new-idx", sg.ToDigest)
	require.Equal(t, byPriority{urgent: 1, high: 1}, sg.Fixes)
	require.Equal(t, []string{advA, advB}, sg.FixedIDs)
	require.Empty(t, sg.Alternatives, "patch and minor fix nothing more")
	require.Empty(t, sg.Notes)
	require.Equal(t, "Debian 12 supported until 2028-06-30", sg.EOL)
	require.Equal(t, rnow, sg.ComputedAt)
	require.Contains(t, got.Candidates, store.CandidateDigest{Tag: "1.30.6", Tier: model.TierRefresh, Platform: "linux/amd64", Digest: "sha256:new-amd64"})
	require.Equal(t, []string{"1.30.6", "1.30.7", "1.31.9"}, tags(got.Candidates))

	require.NotEmpty(t, rg.acq.reqs)
	require.Equal(t, sbom.Request{Repo: nginx, Digest: "sha256:new-amd64", IndexDigest: "sha256:new-idx", Platform: "linux/amd64",
		Creds: registry.CredSet{Namespace: "shop", ServiceAccount: "web", PullSecrets: []string{"regcred"}}}, rg.acq.reqs[0])

	fs, err := rg.st.FindingsForOwner(rctx, webKey)
	require.NoError(t, err)
	require.Len(t, fs, 2)
	for _, f := range fs {
		require.NotNil(t, f.Suggestion, f.AdvisoryID)
		require.Equal(t, "sha256:new-idx", f.Suggestion.ToDigest)
	}

	ts := rg.upgradeTransitions()
	require.Len(t, ts, 2)
	priorities := map[string]model.Priority{}
	for _, tr := range ts {
		require.Equal(t, model.StateOpen, tr.FromState)
		require.Equal(t, model.StateOpen, tr.ToState)
		require.Equal(t, tr.FromPriority, tr.ToPriority)
		require.Equal(t, webRef, tr.Owner)
		require.Equal(t, model.FindingFingerprint("default", webRef, nginx, tr.AdvisoryID), tr.Fingerprint)
		priorities[tr.AdvisoryID] = tr.ToPriority
	}
	require.Equal(t, map[string]model.Priority{advA: urgent, advB: high}, priorities)
}

func TestResolver_MaxCandidatesPerRepo(t *testing.T) {
	rg := newRig(t)
	rg.r.o.Config.Upgrades.MaxCandidatesPerRepo = 2
	rg.resolve()
	require.Equal(t, []string{"sha256:new-amd64", "sha256:c77-amd64"}, rg.acq.digests(), "refresh, then the best patch 1.30.7")
	require.Equal(t, []string{"1.30.6", "1.30.7"}, tags(rg.suggestion().Candidates))
}

func TestResolver_ScoresEveryOwnerArch(t *testing.T) {
	rg := newRig(t)
	rg.setOwner(func(o *model.Owner) { o.Arch = []string{"amd64", "arm64"} })
	rg.r.o.Config.Upgrades.MaxCandidatesPerRepo = 1
	rg.sc.byDigest = map[string][]model.Finding{"sha256:new-arm64": {cf(advA, urgent)}}
	rg.resolve()

	require.Equal(t, []string{"linux/amd64", "linux/arm64"}, rg.reg.platforms)
	got := rg.suggestion()
	sg := got.Suggestion
	require.Equal(t, model.TierRefresh, sg.Tier, "fixing B is the best net change")
	require.Equal(t, byPriority{high: 1}, sg.Fixes)
	require.Equal(t, byPriority{urgent: 1}, sg.Remaining, "A is fixed on amd64 but not on arm64")
	require.Equal(t, []string{advB}, sg.FixedIDs)
	require.Equal(t, []store.CandidateDigest{
		{Tag: "1.30.6", Tier: model.TierRefresh, Platform: "linux/amd64", Digest: "sha256:new-amd64"},
		{Tag: "1.30.6", Tier: model.TierRefresh, Platform: "linux/arm64", Digest: "sha256:new-arm64"},
	}, got.Candidates)
}

func TestResolver_MajorNeverRecommended(t *testing.T) {
	rg := newRig(t)
	rg.reg.tags = append(rg.reg.tags, "2.0.0")
	rg.sc.def = []model.Finding{cf(advA, urgent), cf(advB, high)}
	rg.sc.byDigest = map[string][]model.Finding{"sha256:c200-amd64": nil}
	rg.resolve()

	sg := rg.suggestion().Suggestion
	require.Equal(t, model.TierNone, sg.Tier)
	require.Empty(t, sg.ToTag)
	require.Len(t, sg.Alternatives, 1)
	alt := sg.Alternatives[0]
	require.Equal(t, model.TierMajor, alt.Tier)
	require.Equal(t, "2.0.0", alt.ToTag)
	require.Equal(t, "sha256:c200-idx", alt.ToDigest)
	require.Equal(t, byPriority{urgent: 1, high: 1}, alt.Fixes)
	require.Empty(t, sg.Notes)
	require.Empty(t, rg.upgradeTransitions(), "tier none announces nothing")
}

func TestResolver_NoUpgradePath(t *testing.T) {
	rg := newRig(t)
	rg.putImage(curAMD64, curIdx, "11")
	rg.reg.tags = []string{"latest", "sha256-" + strings.Repeat("ab", 32) + ".sig", "sha256-" + strings.Repeat("cd", 32), "1.30.6-metadata"}
	rg.reg.resolve["1.30.6"] = curIdx
	rg.resolve()

	got := rg.suggestion()
	require.Equal(t, model.TierNone, got.Suggestion.Tier)
	require.Equal(t, []string{"no upgrade path in this repository"}, got.Suggestion.Notes)
	require.Equal(t, "Debian 11 reached end of life 2026-08-31", got.Suggestion.EOL)
	require.Empty(t, got.Candidates)
	require.Empty(t, rg.acq.reqs)
}

func TestResolver_SupportUnknown(t *testing.T) {
	rg := newRig(t)
	rg.putImage(curAMD64, curIdx, "99") // a Debian release the lifecycle data does not know
	rg.resolve()
	require.Equal(t, "unknown", rg.suggestion().Suggestion.EOL)
}

func TestResolver_CandidateFailureSkipsCandidate(t *testing.T) {
	rg := newRig(t)
	rg.acq.errs = map[string]error{"sha256:c77-amd64": sbom.ErrQuarantined}
	rg.resolve()

	got := rg.suggestion()
	require.Equal(t, model.TierRefresh, got.Suggestion.Tier)
	require.Equal(t, []string{"1.30.6", "1.31.9"}, tags(got.Candidates), "the quarantined patch is skipped")
}

func TestResolver_ListTagsFailureKeepsRefresh(t *testing.T) {
	rg := newRig(t)
	rg.reg.listErr = errors.New("tags/list: denied")
	rg.resolve()

	got := rg.suggestion()
	require.Equal(t, model.TierRefresh, got.Suggestion.Tier)
	require.Equal(t, "sha256:new-idx", got.Suggestion.ToDigest)
	require.Equal(t, []string{"1.30.6"}, tags(got.Candidates), "only the refresh is scored when the tags cannot be listed")
	require.Empty(t, got.Suggestion.Notes, "a repository whose tags could not be listed is not called a dead end")
	require.Len(t, rg.upgradeTransitions(), 2)
}

func TestResolver_FailedPassKeepsStoredSuggestion(t *testing.T) {
	rg := newRig(t)
	rg.resolve()
	stored := rg.suggestion()
	rg.now = rnow.Add(24 * time.Hour)

	// the refresh tag does not resolve and the tags cannot be listed: no candidate at all
	rg.reg.listErr = errors.New("tags/list: unavailable")
	delete(rg.reg.resolve, "1.30.6")
	rg.resolve()
	require.Equal(t, stored, rg.suggestion(), "a pass in which nothing survived leaves the stored suggestion")

	// every candidate is found, and every one fails to catalogue
	rg.reg.listErr = nil
	rg.reg.resolve["1.30.6"] = "sha256:new-idx"
	rg.acq.errs = map[string]error{"sha256:new-amd64": sbom.ErrQuarantined, "sha256:c77-amd64": sbom.ErrQuarantined,
		"sha256:c319-amd64": sbom.ErrQuarantined}
	rg.resolve()
	require.Equal(t, stored, rg.suggestion())
	require.Len(t, rg.upgradeTransitions(), 2)
}

func TestResolver_FailedPassWithoutStoredSuggestion(t *testing.T) {
	rg := newRig(t)
	rg.reg.listErr = errors.New("tags/list: denied")
	rg.reg.resolve["1.30.6"] = curIdx // no refresh either
	rg.resolve()

	got := rg.suggestion()
	require.Equal(t, model.TierNone, got.Suggestion.Tier, "with nothing stored, the tier-none result is stored")
	require.Empty(t, got.Suggestion.Notes, "a repository whose tags could not be listed is not called a dead end")
	require.Empty(t, got.Candidates)
	require.Empty(t, rg.upgradeTransitions())
}

func TestResolver_CandidateDeltaMarksStale(t *testing.T) {
	rg := newRig(t)
	rg.resolve()
	stored := rg.suggestion()
	require.False(t, stored.Stale)
	require.Empty(t, rg.r.Pending())

	rg.r.MatchesReplaced(rctx, []string{"sha256:new-amd64"})
	got := rg.suggestion()
	require.True(t, got.Stale, "a re-matched candidate marks the suggestion stale")
	require.Equal(t, stored.Suggestion, got.Suggestion, "it stands until the owner is resolved again")
	require.Equal(t, []string{webKey}, rg.r.Pending())
	fs, err := rg.st.FindingsForOwner(rctx, webKey)
	require.NoError(t, err)
	for _, f := range fs {
		require.NotNil(t, f.Suggestion, f.AdvisoryID)
	}

	rg.r.MatchesReplaced(rctx, []string{"sha256:unrelated"})
	require.Equal(t, []string{webKey}, rg.r.Pending(), "queued once")

	rg.r.resolveNext(rctx)
	require.False(t, rg.suggestion().Stale, "resolving the owner again stores a current suggestion")
}

func TestResolver_UpgradeAppliedStillAffected(t *testing.T) {
	rg := newRig(t)
	rg.sc.byDigest = map[string][]model.Finding{"sha256:new-amd64": {cf(advA, urgent), cf(advB, high)}}
	rg.resolve()
	prev := rg.suggestion()
	require.Equal(t, "1.30.7", prev.Suggestion.ToTag)
	require.Contains(t, prev.Candidates, store.CandidateDigest{Tag: "1.30.7", Tier: model.TierPatch, Platform: "linux/amd64", Digest: "sha256:c77-amd64"})

	rg.r.OwnersRecomputed(rctx, []string{webKey})
	require.Empty(t, rg.r.Pending(), "the owner does not run a candidate yet")

	// 1.30.7 is rolled out: B resolves, A is still there
	rg.putImage("sha256:c77-amd64", "sha256:c77-idx", "12")
	rg.setOwner(func(o *model.Owner) {
		o.Containers[0].ImageRef, o.Containers[0].Digest = "nginx:1.30.7", "sha256:c77-amd64"
	})
	resolved := rg.finding(advB, high, curAMD64)
	at := rnow
	resolved.State, resolved.ResolvedAt = model.StateResolved, &at
	require.NoError(t, rg.st.ApplyFindings(rctx, []model.Finding{rg.finding(advA, urgent, "sha256:c77-amd64"), resolved}, nil))

	rg.r.OwnersRecomputed(rctx, []string{webKey})
	require.Equal(t, []string{webKey}, rg.r.Pending())
	require.NoError(t, rg.st.SetCursor(rctx, dailyCursor, rnow.Unix()))
	restarted := NewResolver(rg.r.o) // a restart loses the in-memory queue
	restarted.startup(rctx)
	require.Equal(t, []string{webKey}, restarted.Pending(), "an owner that runs a scored candidate is queued again")

	rg.resolve()
	sg := rg.suggestion().Suggestion
	require.Equal(t, "1.30.7", sg.FromTag)
	require.Contains(t, sg.Notes, "upgrade applied, still affected: "+advA)
	toResolve, err := rg.st.OwnersToResolve(rctx)
	require.NoError(t, err)
	require.NotContains(t, toResolve, webKey, "the resolution keeps no candidate the owner runs")
}

func TestResolver_AppliedNoteLastsUntilFixed(t *testing.T) {
	rg := newRig(t)
	const advC = "CVE-2026-1003"
	rg.sc.byDigest = map[string][]model.Finding{"sha256:new-amd64": {cf(advA, urgent), cf(advB, high)}}
	rg.resolve()
	require.Equal(t, "1.30.7", rg.suggestion().Suggestion.ToTag)

	// 1.30.7 is rolled out: B resolves, A is still there, and C is new
	rg.putImage("sha256:c77-amd64", "sha256:c77-idx", "12")
	rg.setOwner(func(o *model.Owner) {
		o.Containers[0].ImageRef, o.Containers[0].Digest = "nginx:1.30.7", "sha256:c77-amd64"
	})
	resolved := func(f model.Finding) model.Finding {
		at := rnow
		f.State, f.ResolvedAt = model.StateResolved, &at
		return f
	}
	require.NoError(t, rg.st.ApplyFindings(rctx, []model.Finding{rg.finding(advA, urgent, "sha256:c77-amd64"),
		resolved(rg.finding(advB, high, curAMD64)), rg.finding(advC, high, "sha256:c77-amd64")}, nil))
	rg.resolve()
	got := rg.suggestion()
	require.Contains(t, got.Suggestion.Notes, "upgrade applied, still affected: "+advA)
	require.Equal(t, &store.AppliedUpgrade{Tag: "1.30.7", Tier: model.TierPatch, Digests: []string{"sha256:c77-amd64"},
		FixedIDs: []string{advA, advB}}, got.Applied)
	require.NotEqual(t, "1.30.7", got.Suggestion.ToTag, "the new suggestion moves on from the applied upgrade")

	// the next pass resolves from that new suggestion, and the note stays while A is open
	rg.now = rnow.Add(24 * time.Hour)
	rg.resolve()
	got = rg.suggestion()
	require.Contains(t, got.Suggestion.Notes, "upgrade applied, still affected: "+advA)
	require.NotNil(t, got.Applied)

	// A is fixed: the note and the applied upgrade go
	require.NoError(t, rg.st.ApplyFindings(rctx, []model.Finding{resolved(rg.finding(advA, urgent, "sha256:c77-amd64"))}, nil))
	rg.resolve()
	got = rg.suggestion()
	require.Empty(t, got.Suggestion.Notes)
	require.Nil(t, got.Applied)
}

func TestResolver_ConsumeQueuesOwnersLeavingQualifying(t *testing.T) {
	rg := newRig(t)
	rg.resolve()                            // webKey holds a suggestion
	_, err := rg.r.ConsumeTransitions(rctx) // its UpgradeAvailable transitions queue nothing
	require.NoError(t, err)
	require.Empty(t, rg.r.Pending())
	cart := model.OwnerRef{Kind: "Deployment", Namespace: "shop", Name: "cart"} // holds none
	leave := func(ref model.OwnerRef, id string, toState model.FindingState, from, to model.Priority) model.Transition {
		return model.Transition{Fingerprint: model.FindingFingerprint("default", ref, nginx, id), Owner: ref, AdvisoryID: id,
			FromState: model.StateOpen, ToState: toState, FromPriority: from, ToPriority: to, Trigger: model.TriggerPriorityChange, At: rnow}
	}
	for _, tc := range []struct {
		name string
		t    model.Transition
		want []string
	}{
		{"resolved", leave(webRef, advB, model.StateResolved, high, high), []string{webKey}},
		{"excepted", leave(webRef, advB, model.StateExcepted, high, high), []string{webKey}},
		{"lowered below medium", leave(webRef, advB, model.StateOpen, high, low), []string{webKey}},
		{"lowered within qualifying", leave(webRef, advB, model.StateOpen, high, medium), nil},
		{"was not qualifying", leave(webRef, advB, model.StateResolved, low, low), nil},
		{"owner without a suggestion", leave(cart, advB, model.StateResolved, high, high), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rg.r.dequeue(webKey)
			require.NoError(t, rg.st.ApplyFindings(rctx, nil, []model.Transition{tc.t}))
			n, err := rg.r.ConsumeTransitions(rctx)
			require.NoError(t, err)
			require.Equal(t, 1, n)
			if tc.want == nil {
				require.Empty(t, rg.r.Pending())
			} else {
				require.Equal(t, tc.want, rg.r.Pending())
			}
		})
	}
}

func TestResolver_StartupQueuesUnresolvedOwners(t *testing.T) {
	rg := newRig(t)
	rg.resolve() // webKey holds a current suggestion
	require.NoError(t, rg.st.SetCursor(rctx, dailyCursor, rnow.Unix()))
	api := model.OwnerRef{Kind: "Deployment", Namespace: "shop", Name: "api"}
	f := rg.finding("CVE-2026-1009", high, curAMD64)
	f.Owner, f.Fingerprint = api, model.FindingFingerprint("default", api, nginx, f.AdvisoryID)
	require.NoError(t, rg.st.ApplyFindings(rctx, []model.Finding{f}, nil))

	rg.r.startup(rctx)
	require.Equal(t, []string{api.Key()}, rg.r.Pending(), "a qualifying owner without a suggestion is queued; no daily pass is due")

	rg.r.dequeue(api.Key())
	rg.r.MatchesReplaced(rctx, []string{"sha256:new-amd64"})
	restarted := NewResolver(rg.r.o) // a restart loses the in-memory queue
	restarted.startup(rctx)
	require.Equal(t, []string{api.Key(), webKey}, restarted.Pending(), "a stale suggestion's owner is queued again")
}

func TestResolver_StartupConsumesBeforeDailyPass(t *testing.T) {
	rg := newRig(t)
	created := model.Transition{Fingerprint: rg.finding(advA, urgent, curAMD64).Fingerprint, Owner: webRef, AdvisoryID: advA,
		ToState: model.StateOpen, ToPriority: urgent, Trigger: model.TriggerNewAdvisory, At: rnow}
	require.NoError(t, rg.st.ApplyFindings(rctx, nil, []model.Transition{created}))

	rg.r.startup(rctx) // the last daily pass is older than a day: it never ran
	require.Empty(t, rg.r.Pending(), "the daily pass resolved and dequeued the owner the outbox queued")
	require.Len(t, rg.acq.reqs, 3, "each candidate is catalogued once")
	rg.suggestion()
	cur, err := rg.st.Cursor(rctx, transitionsCursor)
	require.NoError(t, err)
	require.Positive(t, cur)
	last, err := rg.st.Cursor(rctx, dailyCursor)
	require.NoError(t, err)
	require.Equal(t, rnow.Unix(), last)
}

func TestResolver_UnknownVersionHasNoPathNote(t *testing.T) {
	rg := newRig(t)
	rg.setOwner(func(o *model.Owner) { o.Containers[0].ImageRef = "nginx:mainline-build" })
	rg.reg.resolve["mainline-build"] = curIdx // no refresh either
	rg.resolve()

	got := rg.suggestion()
	require.Equal(t, model.TierNone, got.Suggestion.Tier)
	require.Equal(t, []string{"current version unknown"}, got.Suggestion.Notes, "tags were never listed, so no path is claimed")
}

func TestResolver_ConsumeTransitions(t *testing.T) {
	rg := newRig(t)
	at := func(ref model.OwnerRef, id string, p model.Priority, fixable bool) model.Finding {
		return model.Finding{Fingerprint: model.FindingFingerprint("default", ref, nginx, id), Owner: ref, ImageRepo: nginx,
			AdvisoryID: id, State: model.StateOpen, Priority: p, FixAvailable: fixable}
	}
	created := func(f model.Finding) model.Transition {
		return model.Transition{Fingerprint: f.Fingerprint, Owner: f.Owner, AdvisoryID: f.AdvisoryID, ToState: model.StateOpen,
			ToPriority: f.Priority, Trigger: model.TriggerNewAdvisory, At: rnow}
	}
	qualifying := at(webRef, "CVE-2026-2001", model.PriorityMedium, true)
	tooLow := at(model.OwnerRef{Kind: "Deployment", Namespace: "shop", Name: "cart"}, "CVE-2026-2002", model.PriorityLow, true)
	noFix := at(model.OwnerRef{Kind: "Deployment", Namespace: "shop", Name: "db"}, "CVE-2026-2003", model.PriorityHigh, false)
	announced := at(model.OwnerRef{Kind: "Deployment", Namespace: "web", Name: "api"}, "CVE-2026-2004", model.PriorityHigh, true)
	upgrade := created(announced)
	upgrade.FromState, upgrade.FromPriority, upgrade.Trigger = model.StateOpen, model.PriorityHigh, model.TriggerUpgradeAvailable
	// an open finding that just gained a fix qualifies, though its state and priority are unchanged
	searchRef := model.OwnerRef{Kind: "Deployment", Namespace: "shop", Name: "search"}
	gainedFix := at(searchRef, "CVE-2026-2005", model.PriorityMedium, true)
	fixed := created(gainedFix)
	fixed.FromState, fixed.FromPriority, fixed.Trigger = model.StateOpen, model.PriorityMedium, model.TriggerFixAvailable
	// an open finding whose priority fell does not newly qualify
	lowered := at(model.OwnerRef{Kind: "Deployment", Namespace: "shop", Name: "queue"}, "CVE-2026-2006", model.PriorityMedium, true)
	fell := created(lowered)
	fell.FromState, fell.FromPriority, fell.Trigger = model.StateOpen, model.PriorityHigh, model.TriggerPriorityChange
	require.NoError(t, rg.st.ApplyFindings(rctx, []model.Finding{qualifying, tooLow, noFix, announced, gainedFix, lowered},
		[]model.Transition{created(qualifying), created(tooLow), created(noFix), upgrade, fixed, fell}))

	n, err := rg.r.ConsumeTransitions(rctx)
	require.NoError(t, err)
	require.Equal(t, 6, n)
	require.Equal(t, []string{webKey, searchRef.Key()}, rg.r.Pending())
	all, err := rg.st.TransitionsAfter(rctx, 0, 1000)
	require.NoError(t, err)
	cur, err := rg.st.Cursor(rctx, "upgrade")
	require.NoError(t, err)
	require.Equal(t, all[0].ID-1, cur, "the stored cursor stays below the first transition whose owner is queued")

	n, err = rg.r.ConsumeTransitions(rctx)
	require.NoError(t, err)
	require.Zero(t, n, "reading goes on from the last transition read")

	rg.r.resolveNext(rctx)
	cur, err = rg.st.Cursor(rctx, "upgrade")
	require.NoError(t, err)
	require.Equal(t, all[4].ID-1, cur, "then below the transition that queued the owner still queued")
	rg.r.resolveNext(rctx)
	cur, err = rg.st.Cursor(rctx, "upgrade")
	require.NoError(t, err)
	require.Equal(t, all[len(all)-1].ID, cur, "and at the last transition read once every owner is resolved")
}

// TestResolver_RestartKeepsQueuedOwners (W8): an owner that holds a suggestion and was queued by a
// transition is queued again after a restart, until it is resolved.
func TestResolver_RestartKeepsQueuedOwners(t *testing.T) {
	rg := newRig(t)
	rg.resolve() // webKey holds a suggestion on nginx
	require.NoError(t, rg.st.SetCursor(rctx, dailyCursor, rnow.Unix()))
	_, err := rg.r.ConsumeTransitions(rctx) // its UpgradeAvailable transitions queue nothing
	require.NoError(t, err)
	require.Empty(t, rg.r.Pending())

	const advC = "CVE-2026-1003"
	c := rg.finding(advC, high, curAMD64)
	created := model.Transition{Fingerprint: c.Fingerprint, Owner: webRef, AdvisoryID: advC, ToState: model.StateOpen,
		ToPriority: high, Trigger: model.TriggerNewAdvisory, At: rnow}
	require.NoError(t, rg.st.ApplyFindings(rctx, []model.Finding{c}, []model.Transition{created}))
	_, err = rg.r.ConsumeTransitions(rctx)
	require.NoError(t, err)
	require.Equal(t, []string{webKey}, rg.r.Pending())
	toResolve, err := rg.st.OwnersToResolve(rctx)
	require.NoError(t, err)
	require.Empty(t, toResolve, "nothing else marks the owner: its suggestion is current and covers the repository")

	restarted := NewResolver(rg.r.o) // a restart loses the in-memory queue
	restarted.startup(rctx)
	require.Equal(t, []string{webKey}, restarted.Pending(), "the restart reads the transition again and queues the owner")

	cancelled, cancel := context.WithCancel(rctx)
	cancel()
	restarted.resolveNext(cancelled) // shutdown interrupts the resolution
	require.Empty(t, restarted.Pending())
	again := NewResolver(rg.r.o)
	again.startup(rctx)
	require.Equal(t, []string{webKey}, again.Pending(), "an interrupted resolution is not taken as done")

	again.resolveNext(rctx)
	require.Empty(t, again.Pending())
	last := NewResolver(rg.r.o)
	last.startup(rctx)
	require.Empty(t, last.Pending(), "a resolved owner is not queued again")
}

func TestResolver_NoRefireWhenUnchanged(t *testing.T) {
	rg := newRig(t)
	rg.resolve()
	require.Len(t, rg.upgradeTransitions(), 2)

	rg.now = rnow.Add(24 * time.Hour)
	rg.resolve()
	require.Len(t, rg.upgradeTransitions(), 2, "the same recommendation is not announced again")
	require.Equal(t, rg.now, rg.suggestion().Suggestion.ComputedAt, "the suggestion is still recomputed")
}

func TestResolver_NoRefireAfterCandidateDelta(t *testing.T) {
	rg := newRig(t)
	rg.resolve()
	require.Len(t, rg.upgradeTransitions(), 2)

	rg.r.MatchesReplaced(rctx, []string{"sha256:new-amd64"})
	require.Equal(t, []string{webKey}, rg.r.Pending())
	rg.resolve()
	require.Equal(t, "sha256:new-idx", rg.suggestion().Suggestion.ToDigest, "the re-matched refresh is recommended again")
	require.Len(t, rg.upgradeTransitions(), 2, "the target already announced is not announced again")

	rg.reg.resolve["1.30.6"] = "sha256:newer-idx"
	rg.resolve()
	require.Equal(t, "sha256:newer-idx", rg.suggestion().Suggestion.ToDigest)
	require.Len(t, rg.upgradeTransitions(), 4, "a new target is announced")
}

func TestResolver_ReannouncesAfterRequalifying(t *testing.T) {
	rg := newRig(t)
	rg.resolve()
	require.Len(t, rg.upgradeTransitions(), 2)

	lowered := func(f model.Finding) model.Finding {
		f.Priority = model.PriorityLow
		return f
	}
	require.NoError(t, rg.st.ApplyFindings(rctx, []model.Finding{lowered(rg.finding(advA, urgent, curAMD64)),
		lowered(rg.finding(advB, high, curAMD64))}, nil))
	rg.resolve()
	_, ok, err := rg.st.GetSuggestion(rctx, webKey, nginx)
	require.NoError(t, err)
	require.False(t, ok, "the repository no longer qualifies")
	_, _, ok, err = rg.st.Announced(rctx, webKey, nginx)
	require.NoError(t, err)
	require.False(t, ok, "its announcement goes with the suggestion")

	require.NoError(t, rg.st.ApplyFindings(rctx, []model.Finding{rg.finding(advA, urgent, curAMD64),
		rg.finding(advB, high, curAMD64)}, nil))
	rg.resolve()
	require.Len(t, rg.upgradeTransitions(), 4, "a repository that qualifies again is announced afresh")
}

func TestNextDaily(t *testing.T) {
	next, err := nextDaily(time.Date(2026, 11, 20, 2, 59, 0, 0, time.UTC), "03:00")
	require.NoError(t, err)
	require.Equal(t, time.Date(2026, 11, 20, 3, 0, 0, 0, time.UTC), next)
	next, err = nextDaily(time.Date(2026, 11, 20, 3, 0, 1, 0, time.UTC), "03:00")
	require.NoError(t, err)
	require.Equal(t, time.Date(2026, 11, 21, 3, 0, 0, 0, time.UTC), next)
	_, err = nextDaily(rnow, "3pm")
	require.Error(t, err)
}
