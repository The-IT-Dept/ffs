package agentapi

import (
	"context"
	"database/sql"
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

const (
	workRepo = "registry.example/team/app"
	// workTimeout is the fixture's offer timeout; pastGrace takes an offer made now past its deadline and the
	// grace after it, when it no longer takes a result and forget drops it.
	workTimeout = 30 * time.Minute
	pastGrace   = workTimeout + resultGrace
)

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
	return newWorkFixtureAt(t, filepath.Join(t.TempDir(), "ffs.db"))
}

// newWorkFixtureAt is newWorkFixture with its store at path.
func newWorkFixtureAt(t *testing.T, path string) *workFixture {
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

	st := newStoreAt(t, path)
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
	f.q = NewWorkQueue(WorkOptions{Store: st, Acquirer: f.ingest, Pods: f.pods, PerReport: 3, Timeout: workTimeout,
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

// offered gives node a live offer of each digest, as Offer would, without Offer's selection rules.
func (f *workFixture) offered(node string, digests ...string) {
	f.q.mu.Lock()
	defer f.q.mu.Unlock()
	for _, d := range digests {
		f.q.hold(d, "offer-"+node+"-"+d[len(d)-4:], node, "", f.clk.Now())
	}
}

func sideloadDoc(t *testing.T) []byte {
	t.Helper()
	return syftDoc(t, ubuntu, debPkg("libsideload1", "2.0-1"))
}

func TestWork_SBOMNeedsALiveOfferToThatNode(t *testing.T) {
	f := newWorkFixture(t)
	ctx := context.Background()
	doc := sideloadDoc(t)
	before := f.image(t, dig1)
	f.pods.run("worker-2", dig1)

	// Never offered, though a pod on worker-1 runs it: refused, whatever the outcome.
	for name, res := range map[string]*wire.SBOMResult{
		"syft":        {Node: "worker-1", AgentVersion: "v0.0.1", Digest: dig1, SyftJSON: doc},
		"failure":     {Node: "worker-1", Digest: dig1, Failure: "cataloguer exceeded its memory limit"},
		"unavailable": {Node: "worker-1", Digest: dig1, Unavailable: wire.UnavailableLayersDiscarded},
	} {
		err := f.q.SBOM(ctx, worker1, res)
		require.ErrorIs(t, err, ErrForbidden, name)
		require.Contains(t, err.Error(), dig1+" was not offered to worker-1", name)
	}
	require.Zero(t, f.ingest.count())
	f.requireUntouched(t, dig1, before)

	// A result naming another node than the token's.
	err := f.q.SBOM(ctx, worker1, &wire.SBOMResult{Node: "worker-2", AgentVersion: "v0.0.1", Digest: dig1, SyftJSON: doc})
	require.ErrorIs(t, err, ErrForbidden)
	require.Zero(t, f.ingest.count())

	// Offered to worker-1: worker-2, which also runs it, may not answer for it.
	work, err := f.q.Offer(ctx, "worker-1")
	require.NoError(t, err)
	require.Equal(t, dig1, work[0].Digest)
	err = f.q.SBOM(ctx, worker2, &wire.SBOMResult{ID: work[0].ID, Node: "worker-2", AgentVersion: "v0.0.1", Digest: dig1, SyftJSON: doc})
	require.ErrorIs(t, err, ErrForbidden)
	require.Contains(t, err.Error(), dig1+" was not offered to worker-2")
	require.Zero(t, f.ingest.count())
	f.requireUntouched(t, dig1, before)
	require.True(t, f.live(dig1), "worker-1's offer stands")

	// worker-1's offer is past its deadline and the grace after it: refused too.
	f.clk.Add(pastGrace)
	require.ErrorIs(t, f.q.SBOM(ctx, worker1, &wire.SBOMResult{ID: work[0].ID, Node: "worker-1", Digest: dig1, SyftJSON: doc}),
		ErrForbidden)
	require.Zero(t, f.ingest.count())
	f.requireUntouched(t, dig1, before)

	// A live offer to worker-1: accepted, with its provenance.
	f.offered("worker-1", dig1)
	require.NoError(t, f.q.SBOM(ctx, worker1, &wire.SBOMResult{Node: "worker-1", AgentVersion: "v0.0.2", Digest: dig1, SyftJSON: doc}))
	require.Equal(t, 1, f.ingest.count())
	p, ok := f.provenance(t, dig1)
	require.True(t, ok)
	require.Equal(t, store.AgentProvenance{Digest: dig1, Node: "worker-1", AgentVersion: "v0.0.2", ReceivedAt: f.clk.Now()}, p)
	require.False(t, f.live(dig1), "the offer is released")
	stored := f.image(t, dig1)

	// The image is catalogued from worker-1's SBOM: an offer to worker-2 cannot replace it.
	f.offered("worker-2", dig1)
	other := syftDoc(t, ubuntu)
	err = f.q.SBOM(ctx, worker2, &wire.SBOMResult{Node: "worker-2", AgentVersion: "v0.0.2", Digest: dig1, SyftJSON: other})
	require.ErrorIs(t, err, ErrForbidden)
	require.Contains(t, err.Error(), "another node")
	require.Equal(t, stored, f.image(t, dig1))
	p, _ = f.provenance(t, dig1)
	require.Equal(t, "worker-1", p.Node)
	pkgs, err := f.st.PackagesForImage(ctx, dig1)
	require.NoError(t, err)
	require.Len(t, pkgs, 1, "worker-1's packages stand")
	_, ok = f.job(t, dig1)
	require.False(t, ok, "a refused replacement is not counted against the image")
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

	f.clk.Add(pastGrace)
	require.Equal(t, []string{dig1, dig2, dig3}, f.offer(t, "worker-2"))
	require.Empty(t, f.offer(t, "worker-2"), "worker-2 holds three open requests")
	for _, d := range []string{dig1, dig2, dig3} { // answered, they free its room
		require.NoError(t, f.q.SBOM(ctx, worker2, &wire.SBOMResult{Node: "worker-2", Digest: d, Unavailable: wire.UnavailableNotFound}))
	}
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
		require.Equal(t, &store.AgentProvenance{Digest: dig1, Node: "worker-1", AgentVersion: "v0.0.1", ReceivedAt: t0},
			f.ingest.calls[0].prov)
		p, ok := f.provenance(t, dig1)
		require.True(t, ok)
		require.Equal(t, store.AgentProvenance{Digest: dig1, Node: "worker-1", AgentVersion: "v0.0.1", ReceivedAt: t0}, p)
		_, ok = f.job(t, dig1)
		require.False(t, ok, "an earlier failure is cleared")
		require.False(t, f.live(dig1), "the offer is released")

		f.offered("worker-1", dig2)
		require.NoError(t, f.q.SBOM(ctx, worker1, &wire.SBOMResult{Node: "worker-1", AgentVersion: "v0.0.1", Digest: dig2, SyftJSON: doc}))
		require.Equal(t, sbom.Request{Repo: workRepo, Digest: dig2, IndexDigest: digIndex, Platform: "linux/amd64"}, f.ingest.calls[1].req)
	})

	t.Run("superseded is acknowledged without writing", func(t *testing.T) {
		f := newWorkFixture(t)
		f.ingest.setErr(sbom.ErrSuperseded)
		before := f.image(t, dig1)
		f.offered("worker-1", dig1)
		require.NoError(t, f.q.SBOM(ctx, worker1, &wire.SBOMResult{Node: "worker-1", Digest: dig1, SyftJSON: doc}))
		f.requireUntouched(t, dig1, before)
		require.False(t, f.live(dig1))
	})

	t.Run("failures quarantine after two", func(t *testing.T) {
		f := newWorkFixture(t)
		res := &wire.SBOMResult{Node: "worker-1", Digest: dig3, Failure: "cataloguer exceeded its memory limit"}
		f.offered("worker-1", dig3)
		require.NoError(t, f.q.SBOM(ctx, worker1, res))
		require.False(t, f.live(dig3))
		j, ok := f.job(t, dig3)
		require.True(t, ok)
		require.Equal(t, 1, j.Attempts)
		require.True(t, j.QuarantinedUntil.IsZero())
		require.Equal(t, "cataloguer exceeded its memory limit", j.LastError)
		require.Equal(t, "worker-1", j.LastNode)

		f.offered("worker-1", dig3)
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
		f.offered("worker-1", dig1, dig3)
		require.NoError(t, f.q.SBOM(ctx, worker1, &wire.SBOMResult{Node: "worker-1", Digest: dig1, SyftJSON: doc}))
		require.False(t, f.live(dig1), "a counted refusal releases the offer")
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
		f.offered("worker-1", dig1)
		err := f.q.SBOM(ctx, worker1, &wire.SBOMResult{Node: "worker-1", Digest: dig1, SyftJSON: doc})
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrForbidden)
		require.NotErrorIs(t, err, ErrBadRequest)
		f.requireUntouched(t, dig1, before)
		require.True(t, f.live(dig1), "the offer stays for the agent's retry")

		f.ingest.setErr(nil)
		require.NoError(t, f.q.SBOM(ctx, worker1, &wire.SBOMResult{Node: "worker-1", Digest: dig1, SyftJSON: doc}))
		require.False(t, f.live(dig1))
	})

	t.Run("layers discarded on every holder", func(t *testing.T) {
		f := newWorkFixture(t)
		res := &wire.SBOMResult{Node: "worker-1", Digest: dig4, Unavailable: wire.UnavailableLayersDiscarded}
		before := f.image(t, dig4)
		f.offered("worker-1", dig4)
		require.NoError(t, f.q.SBOM(ctx, worker1, res))
		f.requireUntouched(t, dig4, before) // worker-2 still holds it complete

		require.NoError(t, f.st.ReplaceNodeImages(ctx, "worker-2", []model.NodeImage{
			{Digest: dig4, Kind: "manifest", Source: "content-store"}, // held, but incomplete
		}))
		f.offered("worker-1", dig4)
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
			for _, d := range []string{dig2, dig3, dig4} { // skipped, they free worker-1's room
				require.NoError(t, f.q.SBOM(ctx, worker1, &wire.SBOMResult{Node: "worker-1", Digest: d, Unavailable: wire.UnavailableSkipped}))
			}
			f.clk.Add(time.Minute)
			require.Equal(t, []string{dig1, dig2, dig3}, f.offer(t, "worker-1"), "declined until now+6h")
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

	t.Run("an image no longer tracked is acknowledged", func(t *testing.T) {
		f := newWorkFixture(t)
		gone := hexDigest("e")
		f.offered("worker-1", gone) // offered, then pruned
		require.NoError(t, f.q.SBOM(ctx, worker1, &wire.SBOMResult{Node: "worker-1", Digest: gone, SyftJSON: doc}))
		require.False(t, f.live(gone))
		require.Zero(t, f.ingest.count())
		_, ok := f.provenance(t, gone)
		require.False(t, ok)
	})
}

// TestWork_ExpiredOffersCountTowardQuarantine: an offer the agent reached but sent no result for before it
// expired (the agent killed cataloguing it) counts as a failure, so an image that keeps killing collectors is
// quarantined after the usual two and no longer offered (spec §9.3). The agent works through its requests in
// order, so the images offered with it, which it never got to, are not counted.
func TestWork_ExpiredOffersCountTowardQuarantine(t *testing.T) {
	f := newWorkFixture(t)
	requireAttempts := func(t *testing.T, digest string, want int) {
		t.Helper()
		j, ok := f.job(t, digest)
		if want == 0 {
			require.False(t, ok, "%s is not counted", digest)
			return
		}
		require.True(t, ok, digest)
		require.Equal(t, want, j.Attempts, digest)
		require.Equal(t, "worker-1", j.LastNode)
		require.Equal(t, "the node agent sent no result before the request expired", j.LastError)
	}
	require.Equal(t, []string{dig1, dig2, dig3}, f.offer(t, "worker-1"))

	// dig1 kills the collector: no result for dig1, and dig2 and dig3 are never started.
	f.clk.Add(pastGrace)
	require.Equal(t, []string{dig1, dig2, dig3}, f.offer(t, "worker-1"), "offered again after one failure")
	requireAttempts(t, dig1, 1)
	requireAttempts(t, dig2, 0)
	requireAttempts(t, dig3, 0)
	j, _ := f.job(t, dig1)
	require.True(t, j.QuarantinedUntil.IsZero())

	f.clk.Add(pastGrace) // and again
	require.Equal(t, []string{dig2, dig3, dig4}, f.offer(t, "worker-1"), "dig1 is quarantined; dig2 and dig3 are not")
	requireAttempts(t, dig1, 2)
	j, _ = f.job(t, dig1)
	require.Equal(t, f.clk.Now().Add(24*time.Hour), j.QuarantinedUntil)
	requireAttempts(t, dig2, 0)
	requireAttempts(t, dig3, 0)

	// dig2's result arrives in time, so the agent got to dig3, which expires; dig4 was behind dig3.
	require.NoError(t, f.q.SBOM(context.Background(), worker1, &wire.SBOMResult{Node: "worker-1", Digest: dig2, SyftJSON: sideloadDoc(t)}))
	f.clk.Add(pastGrace)
	require.Equal(t, []string{dig3, dig4}, f.offer(t, "worker-1"), "dig2 is catalogued")
	requireAttempts(t, dig2, 0)
	requireAttempts(t, dig3, 1)
	requireAttempts(t, dig4, 0)
}

// TestWork_ExpiredOffersQueuedBehindAStallAreNotCounted: offers made while an earlier unanswered offer to
// the same agent process was live sat in its queue, whichever report they came with; an agent that restarted
// starts a new queue; a result the controller could not store yet answers its offer.
func TestWork_ExpiredOffersQueuedBehindAStallAreNotCounted(t *testing.T) {
	ctx := context.Background()
	attempts := func(t *testing.T, f *workFixture, digest string) int {
		t.Helper()
		j, _ := f.job(t, digest)
		return j.Attempts
	}

	t.Run("a later report's offer waits behind the stalled job", func(t *testing.T) {
		f := newWorkFixture(t)
		f.q.o.PerReport = 2
		require.Equal(t, []string{dig1, dig2}, f.offer(t, "worker-1"))
		f.clk.Add(5 * time.Minute)
		require.NoError(t, f.q.SBOM(ctx, worker1, &wire.SBOMResult{Node: "worker-1", Digest: dig1, SyftJSON: sideloadDoc(t)}))
		f.clk.Add(5 * time.Minute) // a report between jobs brings one more request, while dig2 is open
		require.Equal(t, []string{dig3}, f.offer(t, "worker-1"))
		f.clk.Add(pastGrace) // the agent died on dig2; dig3 was queued behind it
		require.Equal(t, []string{dig2, dig3}, f.offer(t, "worker-1"))
		require.Equal(t, 1, attempts(t, f, dig2))
		require.Zero(t, attempts(t, f, dig3), "dig3 was queued behind dig2")

		// A stall that ended before an offer was made does not excuse it.
		f.clk.Add(pastGrace)
		require.Equal(t, []string{dig3, dig4}, f.offer(t, "worker-1"), "dig2 is quarantined")
		require.Equal(t, 2, attempts(t, f, dig2))
		require.Zero(t, attempts(t, f, dig3), "queued behind dig2 again")
		f.clk.Add(pastGrace)
		f.offer(t, "worker-1")
		require.Equal(t, 1, attempts(t, f, dig3), "dig3 was the first request")
	})

	t.Run("an agent that restarted starts a new queue", func(t *testing.T) {
		f := newWorkFixture(t)
		f.q.o.PerReport = 2
		require.Equal(t, []string{dig1, dig2}, f.offer(t, "worker-1"))
		f.clk.Add(time.Minute)
		require.NoError(t, f.q.SBOM(ctx, worker1, &wire.SBOMResult{Node: "worker-1", Digest: dig1, SyftJSON: sideloadDoc(t)}))
		f.clk.Add(4 * time.Minute) // dig2 kills the collector, which comes back as a new process
		applied, err := f.st.AcceptAgentReport(ctx, store.AgentReport{Node: "worker-1", AgentVersion: "v0.0.1",
			BootID: "boot-worker-1", Instance: "after-restart", StartedAt: f.clk.Now(), Seq: 1, At: f.clk.Now()})
		require.NoError(t, err)
		require.True(t, applied)
		require.Equal(t, []string{dig3}, f.offer(t, "worker-1"), "the new process gets the node's room left")
		f.clk.Add(pastGrace) // dig3 kills the new process too
		f.offer(t, "worker-1")
		require.Equal(t, 1, attempts(t, f, dig2))
		require.Equal(t, 1, attempts(t, f, dig3), "dig3 was the first request of the new process")
	})

	t.Run("a result that could not be stored answers the offer", func(t *testing.T) {
		f := newWorkFixture(t)
		require.Equal(t, []string{dig1, dig2, dig3}, f.offer(t, "worker-1"))
		f.ingest.setErr(&sbom.AcquireError{Kind: sbom.FailTransient, Reason: "acquisition in progress"})
		require.Error(t, f.q.SBOM(ctx, worker1, &wire.SBOMResult{Node: "worker-1", Digest: dig1, SyftJSON: sideloadDoc(t)}))
		require.True(t, f.live(dig1), "the offer stays for the agent's retry")
		f.clk.Add(pastGrace) // the retries fail too; the agent went on to dig2, which expires
		f.offer(t, "worker-1")
		require.Zero(t, attempts(t, f, dig1), "dig1 was answered")
		require.Equal(t, 1, attempts(t, f, dig2))
		require.Zero(t, attempts(t, f, dig3))
	})

	t.Run("stalls are forgotten once no offer can be behind them", func(t *testing.T) {
		f := newWorkFixture(t)
		require.Equal(t, []string{dig1, dig2, dig3}, f.offer(t, "worker-1"))
		f.clk.Add(pastGrace)
		f.offer(t, "worker-1")
		f.q.mu.Lock()
		require.Len(t, f.q.stalled, 1)
		f.q.mu.Unlock()
		f.clk.Add(pastGrace)
		require.NoError(t, f.st.ReplaceNodeImages(ctx, "worker-1", nil)) // nothing more to offer
		f.offer(t, "worker-1")
		f.q.mu.Lock()
		require.Len(t, f.q.stalled, 1, "an offer may still be behind the last stall")
		f.q.mu.Unlock()
		f.clk.Add(pastGrace)
		f.offer(t, "worker-1")
		f.q.mu.Lock()
		defer f.q.mu.Unlock()
		require.Empty(t, f.q.stalled)
		require.Empty(t, f.q.offers)
	})
}

// TestWork_SkippedResultsAreReleasedUncounted: a request the agent did not attempt (too little time left, a
// busy cataloguer, a full scratch volume) is answered skipped: released at once, never counted, and the image
// stays offerable. Only the node it was offered to may skip it.
func TestWork_SkippedResultsAreReleasedUncounted(t *testing.T) {
	f := newWorkFixture(t)
	ctx := context.Background()
	skip := func(d string) *wire.SBOMResult {
		return &wire.SBOMResult{Node: "worker-1", Digest: d, Unavailable: wire.UnavailableSkipped}
	}
	before1, before2 := f.image(t, dig1), f.image(t, dig2)
	require.Equal(t, []string{dig1, dig2, dig3}, f.offer(t, "worker-1"))
	require.NoError(t, f.q.SBOM(ctx, worker1, skip(dig1)))
	require.False(t, f.live(dig1), "the request is released")
	f.requireUntouched(t, dig1, before1)
	require.Equal(t, []string{dig1}, f.offer(t, "worker-1"), "offered again at once: not declined, and worker-1 has room for one")

	f.pods.run("worker-2", dig2)
	err := f.q.SBOM(ctx, worker2, &wire.SBOMResult{Node: "worker-2", Digest: dig2, Unavailable: wire.UnavailableSkipped})
	require.ErrorIs(t, err, ErrForbidden, "dig2 was offered to worker-1")
	require.True(t, f.live(dig2))

	f.clk.Add(workTimeout + time.Minute) // the agent reached dig2 after its deadline
	require.NoError(t, f.q.SBOM(ctx, worker1, skip(dig2)))
	require.False(t, f.live(dig2))
	f.clk.Add(pastGrace)
	f.offer(t, "worker-1")
	f.requireUntouched(t, dig2, before2)
	require.Zero(t, f.ingest.count())
}

// TestWork_ResultsAreTakenUntilTheGraceEnds: an offer takes a result until resultGrace after its deadline, as
// the agent posts the result of a job that used all its time after the deadline. Until then the offer is
// neither forgotten nor offered again, but it no longer takes the node's room.
func TestWork_ResultsAreTakenUntilTheGraceEnds(t *testing.T) {
	f := newWorkFixture(t)
	ctx := context.Background()
	require.Equal(t, []string{dig1, dig2, dig3}, f.offer(t, "worker-1"))
	f.clk.Add(workTimeout + resultGrace - time.Second)
	require.Equal(t, []string{dig4}, f.offer(t, "worker-1"), "dig1..dig3 are past their deadlines but still take a result")
	for _, d := range []string{dig1, dig2, dig3} {
		_, ok := f.job(t, d)
		require.False(t, ok, "%s is not counted yet", d)
	}
	require.NoError(t, f.q.SBOM(ctx, worker1, &wire.SBOMResult{Node: "worker-1", AgentVersion: "v0.0.1", Digest: dig1,
		SyftJSON: sideloadDoc(t)}))
	require.Equal(t, 1, f.ingest.count(), "a result posted within the grace is taken")
	p, ok := f.provenance(t, dig1)
	require.True(t, ok)
	require.Equal(t, "worker-1", p.Node)

	f.clk.Add(time.Second) // the grace has ended
	err := f.q.SBOM(ctx, worker1, &wire.SBOMResult{Node: "worker-1", Digest: dig2, Failure: "timeout: deadline exceeded"})
	require.ErrorIs(t, err, ErrForbidden)
	f.offer(t, "worker-1")
	j, ok := f.job(t, dig2)
	require.True(t, ok)
	require.Equal(t, 1, j.Attempts)
	require.Equal(t, reasonOfferExpired, j.LastError, "counted as an expiry, not as the late failure")
	_, ok = f.job(t, dig3)
	require.False(t, ok, "queued behind dig2")
}

// TestWork_OfferCapsANodesOpenRequests: a node holds at most PerReport requests before their deadlines,
// however often it reports; answered requests, and requests past their deadlines, leave room.
func TestWork_OfferCapsANodesOpenRequests(t *testing.T) {
	f := newWorkFixture(t)
	ctx := context.Background()
	f.q.o.PerReport = 2
	require.Equal(t, []string{dig1, dig2}, f.offer(t, "worker-1"))
	require.Empty(t, f.offer(t, "worker-1"), "an images report between jobs adds nothing while two are open")
	f.clk.Add(time.Minute)
	require.NoError(t, f.q.SBOM(ctx, worker1, &wire.SBOMResult{Node: "worker-1", Digest: dig1, SyftJSON: sideloadDoc(t)}))
	require.Equal(t, []string{dig3}, f.offer(t, "worker-1"), "one answered: one more")
	require.Empty(t, f.offer(t, "worker-1"))
	f.pods.run("worker-2", dig4)
	require.Equal(t, []string{dig4}, f.offer(t, "worker-2"), "another node has its own room")

	f.clk.Add(workTimeout) // dig2 is past its deadline, in its grace
	require.NoError(t, f.q.SBOM(ctx, worker2, &wire.SBOMResult{Node: "worker-2", Digest: dig4, Unavailable: wire.UnavailableSkipped}))
	require.Equal(t, []string{dig4}, f.offer(t, "worker-1"), "a request past its deadline leaves room")
}

// TestWork_OfferCountsEveryExpiry: an expiry that cannot be recorded (worker-1's, counted first) does not stop
// the others being counted, and Offer returns the errors joined.
func TestWork_OfferCountsEveryExpiry(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "ffs.db")
	f := newWorkFixtureAt(t, path)
	f.q.o.PerReport = 1
	f.pods.run("worker-2", dig1, dig2)
	require.Equal(t, []string{dig1}, f.offer(t, "worker-1"))
	require.Equal(t, []string{dig2}, f.offer(t, "worker-2"))
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	_, err = db.ExecContext(ctx, `CREATE TRIGGER refuse_worker1 BEFORE INSERT ON agent_jobs WHEN NEW.last_node = 'worker-1'
		BEGIN SELECT RAISE(ABORT, 'disk I/O error'); END`)
	require.NoError(t, err)

	f.clk.Add(pastGrace)
	work, err := f.q.Offer(ctx, "worker-1")
	require.ErrorContains(t, err, "counting the expired request of "+dig1+" on worker-1")
	require.ErrorContains(t, err, "disk I/O error")
	require.Nil(t, work)
	j, ok := f.job(t, dig2)
	require.True(t, ok, "dig2's expiry is counted although dig1's, counted first, could not be")
	require.Equal(t, 1, j.Attempts)
	require.Equal(t, "worker-2", j.LastNode)
}

// TestWork_ResultWaitEndsWithTheNodesLastRequest: a node's result may wait for the ingest budget until the
// grace of its last open request ends; a result that waited that long answers the node's requests, so their
// expiry is not counted against the images.
func TestWork_ResultWaitEndsWithTheNodesLastRequest(t *testing.T) {
	f := newWorkFixture(t)
	f.q.o.PerReport = 1
	require.LessOrEqual(t, f.q.ResultWait("worker-1"), time.Duration(0), "no request open to worker-1")
	require.Equal(t, []string{dig1}, f.offer(t, "worker-1"))
	require.Equal(t, pastGrace, f.q.ResultWait("worker-1"))
	require.LessOrEqual(t, f.q.ResultWait("worker-2"), time.Duration(0))
	f.clk.Add(10 * time.Minute)
	f.offered("worker-1", dig3) // a later request
	require.Equal(t, pastGrace, f.q.ResultWait("worker-1"), "until the grace of the last request ends")

	f.q.ResultUnread("worker-1")
	f.clk.Add(pastGrace)
	require.LessOrEqual(t, f.q.ResultWait("worker-1"), time.Duration(0))
	f.offer(t, "worker-1")
	for _, d := range []string{dig1, dig3} {
		_, ok := f.job(t, d)
		require.False(t, ok, "%s: the controller held up the result, not the image", d)
	}
}
