package agentapi

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/agentapi/wire"
	"github.com/the-it-dept/ffs/internal/inventory"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/registry"
	"github.com/the-it-dept/ffs/internal/sbom"
	"github.com/the-it-dept/ffs/internal/store"
)

const workRepo = "registry.example/team/app"

var (
	dig1, dig2, dig3, dig4, dig5 = hexDigest("1"), hexDigest("2"), hexDigest("3"), hexDigest("4"), hexDigest("5")
	dig6, dig7, dig8, dig9       = hexDigest("6"), hexDigest("7"), hexDigest("8"), hexDigest("9")
	digIndex                     = hexDigest("d") // dig2's index
	digManifest                  = hexDigest("c") // the manifest whose config digest is dig1
	worker2                      = Identity{Node: "worker-2", Pod: "ffs-agent-q9r4z", PodUID: "uid-2", ServiceAccount: "ffs-agent", Namespace: "ffs-agent"}
	offerIDPattern               = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// workFixture is a WorkQueue over a store holding dig1..dig9:
//   - dig1 side-loaded: a bare config digest, held by worker-1 as the config of a complete manifest;
//   - dig2 registry auth failure, with index digIndex held complete by worker-1;
//   - dig3 registry unreachable; dig4 not found in the registry; dig5 unparseable (class other);
//   - dig6 side-loaded, held complete by worker-1 but run by no pod there;
//   - dig7 side-loaded, run on worker-1 but held incomplete; dig8 side-loaded and quarantined;
//   - dig9 catalogued.
//
// worker-1's pods run dig1, digIndex, dig3, dig4, dig5, dig7, dig8 and dig9; worker-2 holds dig1..dig4
// complete and runs nothing until a test says so.
type workFixture struct {
	st     *store.Store
	q      *WorkQueue
	ingest *fakeIngest
	pods   *fakePods
	clk    *clock
}

func newWorkFixture(t *testing.T) *workFixture {
	t.Helper()
	ctx := context.Background()
	reasons := map[string]string{
		dig1: inventory.ReasonSideLoadedNoTag,
		dig2: fmt.Sprintf(registry.ReasonUnauthorized, workRepo),
		dig3: fmt.Sprintf(inventory.ReasonUnreachable, workRepo, "dial tcp: i/o timeout"),
		dig4: fmt.Sprintf(registry.ReasonNotFound, workRepo+"@"+dig4),
		dig5: fmt.Sprintf(inventory.ReasonUnparseable, "garbage"),
		dig6: inventory.ReasonSideLoadedNoTag, dig7: inventory.ReasonSideLoadedNoTag, dig8: inventory.ReasonSideLoadedNoTag,
	}
	// The reason formats are Task 8's: a change to their classes must fail here, not silently offer nothing.
	for d, class := range map[string]model.UnresolvableClass{dig1: model.UnresolvableSideLoaded, dig2: model.UnresolvableAuth,
		dig3: model.UnresolvableUnreachable, dig4: model.UnresolvableNotFound, dig5: model.UnresolvableOther} {
		require.Equal(t, class, inventory.ClassifyUnresolvable(reasons[d]), "class of %s", reasons[d])
	}

	st := newStore(t)
	for _, d := range []string{dig1, dig2, dig3, dig4, dig5, dig6, dig7, dig8, dig9} {
		img := model.Image{Digest: d, Repo: workRepo, Platform: "linux/amd64", Status: model.ImageUnresolvable, StatusReason: reasons[d]}
		switch d {
		case dig2:
			img.IndexDigest = digIndex
		case dig9:
			img.Status, img.StatusReason, img.Source, img.CataloguedAt = model.ImageCatalogued, "", "registry", t0
		}
		require.NoError(t, st.UpsertImage(ctx, img))
	}
	for _, node := range []string{"worker-1", "worker-2"} {
		_, err := st.AcceptAgentReport(ctx, store.AgentReport{Node: node, AgentVersion: "v0.0.1", BootID: "boot-" + node,
			StartedAt: t0, Seq: 1, At: t0})
		require.NoError(t, err)
	}
	complete := func(d string) model.NodeImage {
		return model.NodeImage{Digest: d, Kind: "manifest", Complete: true, Source: "content-store"}
	}
	require.NoError(t, st.ReplaceNodeImages(ctx, "worker-1", []model.NodeImage{
		{Digest: digManifest, ConfigDigest: dig1, Kind: "manifest", Complete: true, Source: "content-store"},
		{Digest: digIndex, Kind: "index", Complete: true, Source: "content-store"},
		complete(dig3), complete(dig4), complete(dig5), complete(dig6),
		{Digest: dig7, Kind: "manifest", Source: "content-store"},
		complete(dig8), complete(dig9),
	}))
	require.NoError(t, st.ReplaceNodeImages(ctx, "worker-2", []model.NodeImage{complete(dig1), complete(dig2), complete(dig3), complete(dig4)}))
	for range 2 {
		_, err := st.RecordAgentJobFailure(ctx, dig8, "worker-1", "cataloguer exceeded its memory limit", t0, 2, 24*time.Hour)
		require.NoError(t, err)
	}

	f := &workFixture{st: st, ingest: &fakeIngest{st: st}, pods: newFakePods(), clk: newClock(t0)}
	f.pods.run("worker-1", dig1, digIndex, dig3, dig4, dig5, dig7, dig8, dig9)
	f.q = NewWorkQueue(WorkOptions{Store: st, Acquirer: f.ingest, Pods: f.pods, PerReport: 3, Timeout: 30 * time.Minute,
		Now: f.clk.Now, Log: logr.Discard()})
	return f
}

// offer returns the digests offered to node.
func (f *workFixture) offer(t *testing.T, node string) []string {
	t.Helper()
	work, err := f.q.Offer(context.Background(), node)
	require.NoError(t, err)
	var out []string
	for _, w := range work {
		out = append(out, w.Digest)
	}
	return out
}

func (f *workFixture) image(t *testing.T, digest string) model.Image {
	t.Helper()
	img, ok, err := f.st.GetImage(context.Background(), digest)
	require.NoError(t, err)
	require.True(t, ok)
	return img
}

func (f *workFixture) job(t *testing.T, digest string) (store.AgentJob, bool) {
	t.Helper()
	j, ok, err := f.st.AgentJobOf(context.Background(), digest)
	require.NoError(t, err)
	return j, ok
}

func (f *workFixture) provenance(t *testing.T, digest string) (store.AgentProvenance, bool) {
	t.Helper()
	p, ok, err := f.st.AgentProvenanceOf(context.Background(), digest)
	require.NoError(t, err)
	return p, ok
}

// requireUntouched asserts that nothing was written for digest: the image as before, no provenance and no job.
func (f *workFixture) requireUntouched(t *testing.T, digest string, before model.Image) {
	t.Helper()
	require.Equal(t, before, f.image(t, digest))
	_, ok := f.provenance(t, digest)
	require.False(t, ok, "no provenance for %s", digest)
	_, ok = f.job(t, digest)
	require.False(t, ok, "no job row for %s", digest)
}

func (f *workFixture) live(digest string) bool {
	f.q.mu.Lock()
	defer f.q.mu.Unlock()
	_, ok := f.q.offers[digest]
	return ok
}

func sideloadDoc(t *testing.T) []byte {
	t.Helper()
	return syftDoc(t, ubuntu, debPkg("libsideload1", "2.0-1"))
}

func TestWork_RejectsSBOMForDigestNoPodRunsOnNode(t *testing.T) {
	f := newWorkFixture(t)
	ctx := context.Background()
	doc := sideloadDoc(t)
	before := f.image(t, dig1)

	err := f.q.SBOM(ctx, worker2, &wire.SBOMResult{ID: "0123", Node: "worker-2", AgentVersion: "v0.0.1", Digest: dig1, SyftJSON: doc})
	require.ErrorIs(t, err, ErrForbidden)
	require.Contains(t, err.Error(), "no pod on worker-2 runs "+dig1)
	require.Zero(t, f.ingest.count())
	f.requireUntouched(t, dig1, before)

	err = f.q.SBOM(ctx, worker1, &wire.SBOMResult{Node: "worker-2", AgentVersion: "v0.0.1", Digest: dig1, SyftJSON: doc})
	require.ErrorIs(t, err, ErrForbidden)
	require.Zero(t, f.ingest.count())
	f.requireUntouched(t, dig1, before)

	// Never offered, but a pod on worker-1 runs it: accepted.
	require.NoError(t, f.q.SBOM(ctx, worker1, &wire.SBOMResult{Node: "worker-1", AgentVersion: "v0.0.2", Digest: dig1, SyftJSON: doc}))
	require.Equal(t, 1, f.ingest.count())
	p, ok := f.provenance(t, dig1)
	require.True(t, ok)
	require.Equal(t, store.AgentProvenance{Digest: dig1, Node: "worker-1", AgentVersion: "v0.0.2", ReceivedAt: t0}, p)

	// dig2 is trusted on worker-1 through its index: the pod's imageID names digIndex.
	require.NoError(t, f.q.SBOM(ctx, worker1, &wire.SBOMResult{Node: "worker-1", AgentVersion: "v0.0.2", Digest: dig2, SyftJSON: doc}))
	require.Equal(t, 2, f.ingest.count())
	p, ok = f.provenance(t, dig2)
	require.True(t, ok)
	require.Equal(t, "worker-1", p.Node)
}

func TestWork_OfferRules(t *testing.T) {
	f := newWorkFixture(t)
	ctx := context.Background()
	f.pods.run("worker-2", dig1, dig2, dig3, dig4)

	work, err := f.q.Offer(ctx, "worker-1")
	require.NoError(t, err)
	require.Len(t, work, 3)
	ids := map[string]bool{}
	for i, w := range work {
		require.Equal(t, []string{dig1, dig2, dig3}[i], w.Digest)
		require.Equal(t, t0.Add(30*time.Minute), w.Deadline)
		require.Equal(t, "linux/amd64", w.Platform)
		require.Regexp(t, offerIDPattern, w.ID)
		ids[w.ID] = true
	}
	require.Len(t, ids, 3, "offer IDs are distinct")

	require.Equal(t, []string{dig4}, f.offer(t, "worker-2"), "dig1..dig3 are offered to worker-1 until their deadlines")
	require.Empty(t, f.offer(t, "worker-1"), "nothing left: dig5..dig9 are never offered")

	// dig0 is seen only at the next offer, so it comes after the older images despite its digest.
	dig0 := hexDigest("0")
	require.NoError(t, f.st.UpsertImage(ctx, model.Image{Digest: dig0, Repo: workRepo, Platform: "linux/amd64",
		Status: model.ImageUnresolvable, StatusReason: inventory.ReasonSideLoadedNoTag}))
	rows, err := f.st.NodeImages(ctx, "worker-2")
	require.NoError(t, err)
	require.NoError(t, f.st.ReplaceNodeImages(ctx, "worker-2", append(rows, model.NodeImage{Digest: dig0, Complete: true, Source: "content-store"})))
	f.pods.run("worker-2", dig0)

	f.clk.Add(31 * time.Minute)
	require.Equal(t, []string{dig1, dig2, dig3}, f.offer(t, "worker-2"))
	require.Equal(t, []string{dig4, dig0}, f.offer(t, "worker-2"))

	// PerReport 0 offers nothing and reads nothing.
	closed, err := store.Open(ctx, filepath.Join(t.TempDir(), "closed.db"))
	require.NoError(t, err)
	require.NoError(t, closed.Close())
	q := NewWorkQueue(WorkOptions{Store: closed, Pods: f.pods, PerReport: 0, Timeout: time.Minute, Log: logr.Discard()})
	work, err = q.Offer(ctx, "worker-1")
	require.NoError(t, err)
	require.Nil(t, work)
}

func TestWork_SBOMResultHandling(t *testing.T) {
	ctx := context.Background()
	doc := sideloadDoc(t)

	t.Run("syft json is ingested with provenance", func(t *testing.T) {
		f := newWorkFixture(t)
		_, err := f.st.RecordAgentJobFailure(ctx, dig1, "worker-1", "cataloguer exceeded its memory limit", t0, 2, 24*time.Hour)
		require.NoError(t, err)
		work, err := f.q.Offer(ctx, "worker-1")
		require.NoError(t, err)
		require.Equal(t, dig1, work[0].Digest)
		require.True(t, f.live(dig1))

		cov := model.Coverage{UnattributedELF: 2, Notes: []string{"a note"}}
		require.NoError(t, f.q.SBOM(ctx, worker1, &wire.SBOMResult{ID: work[0].ID, Node: "worker-1", AgentVersion: "v0.0.1",
			Digest: dig1, SyftJSON: doc, Coverage: cov}))
		require.Len(t, f.ingest.calls, 1)
		require.Equal(t, sbom.Request{Repo: workRepo, Digest: dig1, Platform: "linux/amd64"}, f.ingest.calls[0].req)
		require.Equal(t, sbom.Result{SyftJSON: doc, Coverage: cov, Source: sbom.SourceAgent}, f.ingest.calls[0].res)
		p, ok := f.provenance(t, dig1)
		require.True(t, ok)
		require.Equal(t, store.AgentProvenance{Digest: dig1, Node: "worker-1", AgentVersion: "v0.0.1", ReceivedAt: t0}, p)
		_, ok = f.job(t, dig1)
		require.False(t, ok, "an earlier failure is cleared")
		require.False(t, f.live(dig1), "the offer is released")

		require.NoError(t, f.q.SBOM(ctx, worker1, &wire.SBOMResult{Node: "worker-1", AgentVersion: "v0.0.1", Digest: dig2, SyftJSON: doc}))
		require.Equal(t, sbom.Request{Repo: workRepo, Digest: dig2, IndexDigest: digIndex, Platform: "linux/amd64"}, f.ingest.calls[1].req)
	})

	t.Run("superseded is acknowledged without writing", func(t *testing.T) {
		f := newWorkFixture(t)
		f.ingest.setErr(sbom.ErrSuperseded)
		before := f.image(t, dig1)
		require.NoError(t, f.q.SBOM(ctx, worker1, &wire.SBOMResult{Node: "worker-1", Digest: dig1, SyftJSON: doc}))
		f.requireUntouched(t, dig1, before)
	})

	t.Run("failures quarantine after two", func(t *testing.T) {
		f := newWorkFixture(t)
		res := &wire.SBOMResult{Node: "worker-1", Digest: dig3, Failure: "cataloguer exceeded its memory limit"}
		require.NoError(t, f.q.SBOM(ctx, worker1, res))
		j, ok := f.job(t, dig3)
		require.True(t, ok)
		require.Equal(t, 1, j.Attempts)
		require.True(t, j.QuarantinedUntil.IsZero())
		require.Equal(t, "cataloguer exceeded its memory limit", j.LastError)
		require.Equal(t, "worker-1", j.LastNode)

		require.NoError(t, f.q.SBOM(ctx, worker1, res))
		j, _ = f.job(t, dig3)
		require.Equal(t, 2, j.Attempts)
		require.Equal(t, t0.Add(24*time.Hour), j.QuarantinedUntil)
		require.Equal(t, []string{dig1, dig2, dig4}, f.offer(t, "worker-1"))
		require.Zero(t, f.ingest.count())
	})

	t.Run("refused SBOMs count", func(t *testing.T) {
		f := newWorkFixture(t)
		f.ingest.setErr(&sbom.AcquireError{Kind: sbom.FailCounted, Reason: "decoding SBOM"})
		require.NoError(t, f.q.SBOM(ctx, worker1, &wire.SBOMResult{Node: "worker-1", Digest: dig1, SyftJSON: doc}))
		j, ok := f.job(t, dig1)
		require.True(t, ok)
		require.Equal(t, 1, j.Attempts)
		require.True(t, j.QuarantinedUntil.IsZero())
		require.Equal(t, "decoding SBOM", j.LastError)

		f.ingest.setErr(&sbom.AcquireError{Kind: sbom.FailQuarantine, Reason: "SBOM too large"})
		require.NoError(t, f.q.SBOM(ctx, worker1, &wire.SBOMResult{Node: "worker-1", Digest: dig3, SyftJSON: doc}))
		j, ok = f.job(t, dig3)
		require.True(t, ok)
		require.Equal(t, 1, j.Attempts)
		require.Equal(t, t0.Add(24*time.Hour), j.QuarantinedUntil, "a deterministic refusal quarantines at once")
		_, ok = f.provenance(t, dig3)
		require.False(t, ok)
	})

	t.Run("transient failure is returned uncounted", func(t *testing.T) {
		f := newWorkFixture(t)
		f.ingest.setErr(&sbom.AcquireError{Kind: sbom.FailTransient, Reason: "acquisition in progress"})
		before := f.image(t, dig1)
		err := f.q.SBOM(ctx, worker1, &wire.SBOMResult{Node: "worker-1", Digest: dig1, SyftJSON: doc})
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrForbidden)
		require.NotErrorIs(t, err, ErrBadRequest)
		f.requireUntouched(t, dig1, before)
	})

	t.Run("layers discarded on every holder", func(t *testing.T) {
		f := newWorkFixture(t)
		res := &wire.SBOMResult{Node: "worker-1", Digest: dig4, Unavailable: wire.UnavailableLayersDiscarded}
		before := f.image(t, dig4)
		require.NoError(t, f.q.SBOM(ctx, worker1, res))
		f.requireUntouched(t, dig4, before) // worker-2 still holds it complete

		require.NoError(t, f.st.ReplaceNodeImages(ctx, "worker-2", []model.NodeImage{
			{Digest: dig4, Kind: "manifest", Source: "content-store"}, // held, but incomplete
		}))
		require.NoError(t, f.q.SBOM(ctx, worker1, res))
		img := f.image(t, dig4)
		require.Equal(t, inventory.ReasonLayersDiscarded, img.StatusReason)
		require.Equal(t, model.ImageUnresolvable, img.Status)
		_, ok := f.job(t, dig4)
		require.False(t, ok, "never counted")
		require.Zero(t, f.ingest.count())
	})

	for _, why := range []string{wire.UnavailableNotFound, wire.UnavailableTooLarge} {
		t.Run("unavailable "+why+" declines for this node", func(t *testing.T) {
			f := newWorkFixture(t)
			f.pods.run("worker-2", dig1)
			require.Equal(t, []string{dig1, dig2, dig3}, f.offer(t, "worker-1"))
			before := f.image(t, dig1)
			require.NoError(t, f.q.SBOM(ctx, worker1, &wire.SBOMResult{Node: "worker-1", Digest: dig1, Unavailable: why}))
			f.requireUntouched(t, dig1, before)
			require.False(t, f.live(dig1))

			require.Equal(t, []string{dig4}, f.offer(t, "worker-1"), "worker-1 declined dig1")
			require.Equal(t, []string{dig1}, f.offer(t, "worker-2"), "other nodes still get it")

			f.clk.Add(inventory.UnresolvableRetry - time.Minute)
			require.Equal(t, []string{dig2, dig3, dig4}, f.offer(t, "worker-1"))
			f.clk.Add(time.Minute)
			require.Equal(t, []string{dig1}, f.offer(t, "worker-1"), "declined until now+6h")
		})
	}

	t.Run("exactly one outcome", func(t *testing.T) {
		f := newWorkFixture(t)
		for name, res := range map[string]*wire.SBOMResult{
			"none":                 {Node: "worker-1", Digest: dig1},
			"syft and failure":     {Node: "worker-1", Digest: dig1, SyftJSON: doc, Failure: "oom"},
			"syft and unavailable": {Node: "worker-1", Digest: dig1, SyftJSON: doc, Unavailable: wire.UnavailableNotFound},
			"unavailable, failure": {Node: "worker-1", Digest: dig1, Unavailable: wire.UnavailableTooLarge, Failure: "oom"},
			"unknown unavailable":  {Node: "worker-1", Digest: dig1, Unavailable: "gone"},
		} {
			require.ErrorIs(t, f.q.SBOM(ctx, worker1, res), ErrBadRequest, name)
		}
		_, ok := f.job(t, dig1)
		require.False(t, ok)
		require.Zero(t, f.ingest.count())
	})

	t.Run("an untracked image is acknowledged", func(t *testing.T) {
		f := newWorkFixture(t)
		gone := hexDigest("e")
		f.pods.run("worker-1", gone)
		require.NoError(t, f.q.SBOM(ctx, worker1, &wire.SBOMResult{Node: "worker-1", Digest: gone, SyftJSON: doc}))
		require.Zero(t, f.ingest.count())
		_, ok := f.provenance(t, gone)
		require.False(t, ok)
	})
}
