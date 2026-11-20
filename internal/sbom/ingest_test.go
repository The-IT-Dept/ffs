package sbom

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

const grp = "nodegroup:" + "3f9c1a" // any digest string; Ingest does not parse it

func agentRes(t *testing.T) *Result { return &Result{SyftJSON: syftBytes(t, ""), Source: SourceAgent} }

func grpReq() Request { return Request{Repo: "host", Digest: grp, Platform: "linux/amd64"} }

// recv returns the next value of ch, failing the test after 5s.
func recv(t *testing.T, ch <-chan string) string {
	t.Helper()
	select {
	case d := <-ch:
		return d
	case <-time.After(5 * time.Second):
		t.Fatal("nothing was matched")
		return ""
	}
}

// reasonOf returns the Reason of an *AcquireError, "" for any other error.
func reasonOf(err error) string {
	var ae *AcquireError
	if errors.As(err, &ae) {
		return ae.Reason
	}
	return ""
}

func TestIngest_StoresAgentSBOMAndMatchesAsync(t *testing.T) {
	st, clock := acqStore(t), acqClock()
	release := make(chan struct{})
	matched := make(chan string, 4)
	a := NewAcquirer(AcquirerOptions{Store: st, Concurrency: 1, Now: clock.Now,
		OnCatalogued: func(_ context.Context, d string) error { <-release; matched <- d; return nil }})
	startAcq(t, a)
	r := Request{Repo: "host", Digest: grp, Platform: "linux/amd64"}
	require.NoError(t, a.Ingest(ctx, r, agentRes(t))) // returns while the match is still blocked
	img := getImg(t, st, grp)
	require.Equal(t, model.ImageCatalogued, img.Status)
	require.Equal(t, SourceAgent, img.Source)
	require.Equal(t, "host", img.Repo)
	pkgs, _ := st.PackagesForImage(ctx, grp)
	require.NotEmpty(t, pkgs)
	un, _ := st.UnmatchedDigests(ctx, []string{grp})
	require.Equal(t, []string{grp}, un)
	close(release)
	require.Equal(t, grp, <-matched)
	require.Eventually(t, func() bool { un, _ := st.UnmatchedDigests(ctx, []string{grp}); return len(un) == 0 }, 5*time.Second, 5*time.Millisecond)
}

func TestIngest_MatchDetachedFromRequestContext(t *testing.T) {
	st, clock := acqStore(t), acqClock()
	type seen struct {
		err      error
		deadline time.Time
		ok       bool
	}
	proceed := make(chan struct{})
	got := make(chan seen, 1)
	a := NewAcquirer(AcquirerOptions{Store: st, Concurrency: 1, Now: clock.Now, MatchTimeout: time.Minute,
		OnCatalogued: func(c context.Context, _ string) error {
			<-proceed
			dl, ok := c.Deadline()
			got <- seen{c.Err(), dl, ok}
			return nil
		}})
	startAcq(t, a)
	rctx, cancel := context.WithCancel(ctx)
	require.NoError(t, a.Ingest(rctx, grpReq(), agentRes(t)))
	cancel()
	close(proceed)
	var s seen
	select {
	case s = <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("the ingested image was not matched")
	}
	require.NoError(t, s.err, "the match does not run on the request's context")
	require.True(t, s.ok)
	require.False(t, s.deadline.After(time.Now().Add(time.Minute)), "the match is bounded by MatchTimeout")
}

func TestIngest_MatchesOneAtATime(t *testing.T) {
	st, clock := acqStore(t), acqClock()
	var inFlight, maxInFlight atomic.Int32
	matched := make(chan string, 4)
	a := NewAcquirer(AcquirerOptions{Store: st, Concurrency: 2, Now: clock.Now,
		OnCatalogued: func(_ context.Context, d string) error {
			n := inFlight.Add(1)
			for {
				m := maxInFlight.Load()
				if n <= m || maxInFlight.CompareAndSwap(m, n) {
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
			inFlight.Add(-1)
			matched <- d
			return nil
		}})
	startAcq(t, a)
	second := grpReq()
	second.Digest = grp + "b"
	require.NoError(t, a.Ingest(ctx, grpReq(), agentRes(t)))
	require.NoError(t, a.Ingest(ctx, second, agentRes(t)))
	require.ElementsMatch(t, []string{grp, grp + "b"}, []string{recv(t, matched), recv(t, matched)})
	require.EqualValues(t, 1, maxInFlight.Load())
}

func TestIngest_UnmatchedRetriedAtStart(t *testing.T) {
	st, clock := acqStore(t), acqClock()
	var calls atomic.Int32
	a := NewAcquirer(AcquirerOptions{Store: st, Concurrency: 1, Now: clock.Now,
		OnCatalogued: func(context.Context, string) error { calls.Add(1); return nil }})
	require.NoError(t, a.Ingest(ctx, grpReq(), agentRes(t))) // a is never started
	require.Zero(t, calls.Load())
	un, err := st.UnmatchedImages(ctx)
	require.NoError(t, err)
	require.Equal(t, []store.UnmatchedImage{{Digest: grp}}, un)

	matched := make(chan string, 1)
	b := NewAcquirer(AcquirerOptions{Store: st, Concurrency: 1, Now: clock.Now,
		OnCatalogued: func(_ context.Context, d string) error { matched <- d; return nil }})
	startAcq(t, b)
	require.Equal(t, grp, recv(t, matched))
	require.Eventually(t, func() bool {
		un, err := st.UnmatchedImages(ctx)
		return err == nil && len(un) == 0
	}, 5*time.Second, 5*time.Millisecond)
	require.Zero(t, calls.Load())
}

func TestIngest_RejectsNonAgentSource(t *testing.T) {
	st, clock := acqStore(t), acqClock()
	a := NewAcquirer(AcquirerOptions{Store: st, Concurrency: 1, Now: clock.Now})
	require.Error(t, a.Ingest(ctx, grpReq(), &Result{SyftJSON: syftBytes(t, ""), Source: "registry"}))
	require.Error(t, a.Ingest(ctx, grpReq(), nil))
	require.Zero(t, getImgOrZero(st, grp))
}

func TestIngest_RegistryCataloguedIsSuperseded(t *testing.T) {
	st, clock := acqStore(t), acqClock()
	sb := syftBytes(t, "app")
	require.NoError(t, st.UpsertImage(ctx, model.Image{Digest: grp, Repo: "host", Status: model.ImageCatalogued, Source: "registry"}))
	require.NoError(t, st.PutSBOM(ctx, grp, sb, nil))
	a := NewAcquirer(AcquirerOptions{Store: st, Concurrency: 1, Now: clock.Now})
	err := a.Ingest(ctx, grpReq(), agentRes(t))
	require.ErrorIs(t, err, ErrSuperseded)
	got, _, err := st.GetSBOM(ctx, grp)
	require.NoError(t, err)
	require.Equal(t, sb, got)
	require.Equal(t, "registry", getImg(t, st, grp).Source)
}

func TestIngest_RefusalsWriteNothing(t *testing.T) {
	for _, tc := range []struct {
		name   string
		sbom   []byte
		stale  bool
		kind   FailureKind
		reason string
	}{
		{name: "too large", sbom: make([]byte, MaxSBOMBytes+1), kind: FailQuarantine},
		{name: "undecodable", sbom: []byte("{not json"), kind: FailCounted, reason: "decoding SBOM"},
		{name: "stale in-flight record", stale: true, kind: FailCounted, reason: reasonControllerStopped},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, clock := acqStore(t), acqClock()
			if tc.stale {
				_, err := st.BeginAcquire(ctx, grp, clock.Now())
				require.NoError(t, err)
			}
			a := NewAcquirer(AcquirerOptions{Store: st, Concurrency: 1, Now: clock.Now})
			res := agentRes(t)
			if tc.sbom != nil {
				res.SyftJSON = tc.sbom
			}
			err := a.Ingest(ctx, grpReq(), res)
			require.Error(t, err)
			require.Equal(t, tc.kind, KindOf(err), err.Error())
			if tc.reason != "" {
				require.Equal(t, tc.reason, reasonOf(err))
			}
			require.Zero(t, getImgOrZero(st, grp))
			un, err := st.UnmatchedDigests(ctx, []string{grp})
			require.NoError(t, err)
			require.Empty(t, un)
			stale, err := st.BeginAcquire(ctx, grp, clock.Now())
			require.NoError(t, err)
			require.False(t, stale, "the in-flight record is cleared")
		})
	}
}

func TestIngest_BusyDigestIsTransientBothWays(t *testing.T) {
	t.Run("job first", func(t *testing.T) {
		st, clock := acqStore(t), acqClock()
		entered, release := make(chan struct{}), make(chan struct{})
		src := &fakeSource{name: "registry"}
		src.script = func(context.Context, int, Request) (*Result, error) {
			close(entered)
			<-release
			return &Result{SyftJSON: syftBytes(t, ""), Source: "registry"}, nil
		}
		a := NewAcquirer(AcquirerOptions{Store: st, Sources: []Source{src}, Concurrency: 1, Now: clock.Now})
		startAcq(t, a)
		a.Enqueue(acqReq())
		<-entered
		err := a.Ingest(ctx, acqReq(), agentRes(t))
		require.Equal(t, FailTransient, KindOf(err))
		require.Equal(t, reasonInProgress, reasonOf(err))
		close(release)
		require.Eventually(t, func() bool {
			img := getImgOrZero(st, acqDigest)
			return img.Status == model.ImageCatalogued && img.Source == "registry"
		}, 5*time.Second, 5*time.Millisecond)
	})
	t.Run("ingest first", func(t *testing.T) {
		st, clock := acqStore(t), acqClock()
		src := &fakeSource{name: "registry", res: &Result{SyftJSON: syftBytes(t, ""), Source: "registry"}}
		a := NewAcquirer(AcquirerOptions{Store: st, Sources: []Source{src}, Concurrency: 1, Now: clock.Now,
			RetryAfter: 10 * time.Millisecond})
		a.mu.Lock()
		a.ingesting[acqDigest] = true
		a.mu.Unlock()
		startAcq(t, a)
		a.Enqueue(acqReq())
		time.Sleep(50 * time.Millisecond)
		require.Zero(t, src.calls.Load())
		require.Zero(t, getImgOrZero(st, acqDigest).Attempts)
		a.mu.Lock()
		delete(a.ingesting, acqDigest)
		a.mu.Unlock()
		require.Eventually(t, func() bool { return src.calls.Load() == 1 }, 5*time.Second, 5*time.Millisecond)
		require.Eventually(t, func() bool { return getImgOrZero(st, acqDigest).Status == model.ImageCatalogued },
			5*time.Second, 5*time.Millisecond)
		require.Zero(t, getImg(t, st, acqDigest).Attempts)
	})
}

// agentImage catalogues acqDigest from an agent SBOM through a and records its provenance. It returns
// the stored image and SBOM.
func agentImage(t *testing.T, st *store.Store, a *Acquirer, clock *fakeClock) (model.Image, []byte) {
	t.Helper()
	require.NoError(t, a.Ingest(ctx, acqReq(), agentRes(t)))
	require.NoError(t, st.PutAgentProvenance(ctx, store.AgentProvenance{Digest: acqDigest, Node: "worker-1",
		AgentVersion: "v0.1.0", ReceivedAt: clock.Now()}))
	b, _, err := st.GetSBOM(ctx, acqDigest)
	require.NoError(t, err)
	img := getImg(t, st, acqDigest)
	require.Equal(t, SourceAgent, img.Source)
	return img, b
}

func supersedeReq() Request {
	r := acqReq()
	r.Supersede = true
	return r
}

func TestSupersede_ReplacesAgentSBOMAndClearsProvenance(t *testing.T) {
	st, clock := acqStore(t), acqClock()
	matched := make(chan string, 4)
	src := &fakeSource{name: "registry", res: &Result{SyftJSON: syftBytes(t, "app"), Source: "registry"}}
	a := NewAcquirer(AcquirerOptions{Store: st, Sources: []Source{src}, Concurrency: 1, Now: clock.Now,
		OnCatalogued: func(_ context.Context, d string) error { matched <- d; return nil }})
	startAcq(t, a)
	agentImage(t, st, a, clock)
	require.Equal(t, acqDigest, recv(t, matched)) // the agent SBOM's match

	a.Enqueue(supersedeReq())
	require.Eventually(t, func() bool { return getImgOrZero(st, acqDigest).Source == "registry" }, 5*time.Second, 5*time.Millisecond)
	img := getImg(t, st, acqDigest)
	require.Equal(t, model.ImageCatalogued, img.Status)
	require.Equal(t, "app", img.ConfigUser)
	require.Equal(t, acqDigest, recv(t, matched)) // the registry SBOM's match
	_, ok, err := st.AgentProvenanceOf(ctx, acqDigest)
	require.NoError(t, err)
	require.False(t, ok)
	require.EqualValues(t, 1, src.calls.Load())
}

func TestSupersede_FailureChangesNothing(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"unresolvable", &AcquireError{Kind: FailUnresolvable, Reason: "unauthorized"}},
		{"counted", &AcquireError{Kind: FailCounted, Reason: "cataloguer crashed"}},
		{"quarantine", &AcquireError{Kind: FailQuarantine, Reason: "image exceeds the size limit"}},
		{"transient", &AcquireError{Kind: FailTransient, Reason: "rate limited"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, clock := acqStore(t), acqClock()
			src := &fakeSource{name: "registry", err: tc.err}
			a := NewAcquirer(AcquirerOptions{Store: st, Sources: []Source{src}, Concurrency: 1, Now: clock.Now,
				RetryAfter: 10 * time.Millisecond})
			startAcq(t, a)
			before, sb := agentImage(t, st, a, clock)
			a.Enqueue(supersedeReq())
			time.Sleep(100 * time.Millisecond)

			img := getImg(t, st, acqDigest)
			require.Equal(t, before, img)
			require.Equal(t, model.ImageCatalogued, img.Status)
			require.Equal(t, SourceAgent, img.Source)
			require.Zero(t, img.Attempts)
			require.True(t, img.QuarantinedUntil.IsZero())
			require.Empty(t, img.StatusReason)
			got, _, err := st.GetSBOM(ctx, acqDigest)
			require.NoError(t, err)
			require.Equal(t, sb, got)
			_, ok, err := st.AgentProvenanceOf(ctx, acqDigest)
			require.NoError(t, err)
			require.True(t, ok, "the provenance is kept")
			require.EqualValues(t, 1, src.calls.Load(), "a failed supersede is not retried")
			require.Zero(t, a.Stats().Failed)
			require.Zero(t, a.Stats().Quarantined)
		})
	}
}

func TestSupersede_IgnoredUnlessAgentCatalogued(t *testing.T) {
	st, clock := acqStore(t), acqClock()
	require.NoError(t, st.UpsertImage(ctx, model.Image{Digest: acqDigest, Repo: acqReq().Repo, Status: model.ImageCatalogued,
		Source: "registry"}))
	require.NoError(t, st.PutSBOM(ctx, acqDigest, syftBytes(t, ""), nil))
	src := &fakeSource{name: "registry", res: &Result{SyftJSON: syftBytes(t, "app"), Source: "registry"}}
	a := NewAcquirer(AcquirerOptions{Store: st, Sources: []Source{src}, Concurrency: 1, Now: clock.Now})
	startAcq(t, a)
	a.Enqueue(supersedeReq())
	res, err := a.AcquireNow(ctx, supersedeReq()) // joins or follows the queued job
	require.NoError(t, err)
	require.Equal(t, "registry", res.Source)
	require.Zero(t, src.calls.Load())
}

func TestSupersede_StaleAttemptSkipsSources(t *testing.T) {
	st, clock := acqStore(t), acqClock()
	src := &fakeSource{name: "registry", res: &Result{SyftJSON: syftBytes(t, "app"), Source: "registry"}}
	a := NewAcquirer(AcquirerOptions{Store: st, Sources: []Source{src}, Concurrency: 1, Now: clock.Now})
	startAcq(t, a)
	before, _ := agentImage(t, st, a, clock)
	_, err := st.BeginAcquire(ctx, acqDigest, clock.Now()) // left over by a controller that stopped
	require.NoError(t, err)

	_, err = a.AcquireNow(ctx, supersedeReq())
	require.Error(t, err)
	require.Equal(t, FailCounted, KindOf(err))
	require.Equal(t, reasonControllerStopped, reasonOf(err))
	require.Zero(t, src.calls.Load())
	require.Equal(t, before, getImg(t, st, acqDigest))

	// The in-flight record was cleared, so the next supersede tries the source.
	res, err := a.AcquireNow(ctx, supersedeReq())
	require.NoError(t, err)
	require.Equal(t, "registry", res.Source)
	require.EqualValues(t, 1, src.calls.Load())
}

// TestIngestFromNode_NeverReplacesAnotherNodesSBOM: an image catalogued from one node's agent SBOM is not
// replaced by another node's; the same node may replace its own, and the provenance is recorded with it.
func TestIngestFromNode_NeverReplacesAnotherNodesSBOM(t *testing.T) {
	st, clock := acqStore(t), acqClock()
	a := NewAcquirer(AcquirerOptions{Store: st, Concurrency: 1, Now: clock.Now})
	prov := func(node, version string) store.AgentProvenance {
		return store.AgentProvenance{Node: node, AgentVersion: version, ReceivedAt: clock.Now()}
	}
	first := syftBytes(t, "")
	require.NoError(t, a.IngestFromNode(ctx, prov("worker-1", "v0.0.1"), acqReq(), &Result{SyftJSON: first, Source: SourceAgent}))
	p, ok, err := st.AgentProvenanceOf(ctx, acqDigest)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, store.AgentProvenance{Digest: acqDigest, Node: "worker-1", AgentVersion: "v0.0.1", ReceivedAt: clock.Now()}, p)
	img := getImg(t, st, acqDigest)

	other := syftBytes(t, "intruder")
	err = a.IngestFromNode(ctx, prov("worker-2", "v0.0.1"), acqReq(), &Result{SyftJSON: other, Source: SourceAgent})
	require.ErrorIs(t, err, ErrOtherNode)
	got, _, err := st.GetSBOM(ctx, acqDigest)
	require.NoError(t, err)
	require.Equal(t, first, got, "worker-1's SBOM stands")
	require.Equal(t, img, getImg(t, st, acqDigest))
	p, _, err = st.AgentProvenanceOf(ctx, acqDigest)
	require.NoError(t, err)
	require.Equal(t, "worker-1", p.Node)
	stale, err := st.BeginAcquire(ctx, acqDigest, clock.Now())
	require.NoError(t, err)
	require.False(t, stale, "the in-flight record is cleared")
	require.NoError(t, st.EndAcquire(ctx, acqDigest))

	require.NoError(t, a.IngestFromNode(ctx, prov("worker-1", "v0.0.2"), acqReq(), &Result{SyftJSON: other, Source: SourceAgent}))
	got, _, err = st.GetSBOM(ctx, acqDigest)
	require.NoError(t, err)
	require.Equal(t, other, got, "a node may replace its own SBOM")
	p, _, err = st.AgentProvenanceOf(ctx, acqDigest)
	require.NoError(t, err)
	require.Equal(t, "v0.0.2", p.AgentVersion)

	require.Error(t, a.IngestFromNode(ctx, store.AgentProvenance{}, acqReq(), agentRes(t)), "a node is required")
}
