package upgrade

import (
	"context"
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
	resolve   map[string]string
	platforms []string // PlatformManifest platforms, in call order
}

func (f *fakeRegistry) ListTags(context.Context, string, registry.CredSet) ([]string, error) {
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
	require.Empty(t, sg.EOL, "debian 12 is supported")
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
	require.Equal(t, "debian 11 reached end of life 2026-08-31", got.Suggestion.EOL)
	require.Empty(t, got.Candidates)
	require.Empty(t, rg.acq.reqs)
}

func TestResolver_CandidateFailureSkipsCandidate(t *testing.T) {
	rg := newRig(t)
	rg.acq.errs = map[string]error{"sha256:c77-amd64": sbom.ErrQuarantined}
	rg.resolve()

	got := rg.suggestion()
	require.Equal(t, model.TierRefresh, got.Suggestion.Tier)
	require.Equal(t, []string{"1.30.6", "1.31.9"}, tags(got.Candidates), "the quarantined patch is skipped")
}

func TestResolver_InvalidatesOnCandidateDelta(t *testing.T) {
	rg := newRig(t)
	rg.resolve()
	rg.suggestion()
	require.Empty(t, rg.r.Pending())

	rg.r.MatchesReplaced(rctx, []string{"sha256:new-amd64"})
	_, ok, err := rg.st.GetSuggestion(rctx, webKey, nginx)
	require.NoError(t, err)
	require.False(t, ok, "a re-matched candidate withdraws the suggestion")
	require.Equal(t, []string{webKey}, rg.r.Pending())
	fs, err := rg.st.FindingsForOwner(rctx, webKey)
	require.NoError(t, err)
	for _, f := range fs {
		require.Nil(t, f.Suggestion, f.AdvisoryID)
	}

	rg.r.MatchesReplaced(rctx, []string{"sha256:unrelated"})
	require.Equal(t, []string{webKey}, rg.r.Pending(), "queued once")
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
	rg.resolve()
	sg := rg.suggestion().Suggestion
	require.Equal(t, "1.30.7", sg.FromTag)
	require.Contains(t, sg.Notes, "upgrade applied, still affected: "+advA)
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
	require.NoError(t, rg.st.ApplyFindings(rctx, []model.Finding{qualifying, tooLow, noFix, announced},
		[]model.Transition{created(qualifying), created(tooLow), created(noFix), upgrade}))

	n, err := rg.r.ConsumeTransitions(rctx)
	require.NoError(t, err)
	require.Equal(t, 4, n)
	require.Equal(t, []string{webKey}, rg.r.Pending())
	all, err := rg.st.TransitionsAfter(rctx, 0, 1000)
	require.NoError(t, err)
	cur, err := rg.st.Cursor(rctx, "upgrade")
	require.NoError(t, err)
	require.Equal(t, all[len(all)-1].ID, cur)

	n, err = rg.r.ConsumeTransitions(rctx)
	require.NoError(t, err)
	require.Zero(t, n)
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
