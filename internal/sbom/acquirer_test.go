package sbom

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/registry"
	"github.com/the-it-dept/ffs/internal/store"
)

const acqDigest = "sha256:aaaa"

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// fakeSource records calls and returns scripted results.
type fakeSource struct {
	name  string
	calls atomic.Int32
	// script, when set, decides each call (n is 1-based); otherwise res/err are returned.
	script func(ctx context.Context, n int, r Request) (*Result, error)
	res    *Result
	err    error
}

func (f *fakeSource) Name() string { return f.name }

func (f *fakeSource) Acquire(ctx context.Context, r Request) (*Result, error) {
	n := int(f.calls.Add(1))
	if f.script != nil {
		return f.script(ctx, n, r)
	}
	return f.res, f.err
}

func acqStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "ffs.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	return st
}

func acqClock() *fakeClock { return &fakeClock{t: time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)} }

func acqReq() Request {
	return Request{Repo: "docker.io/library/nginx", Digest: acqDigest, IndexDigest: "sha256:index", Platform: "linux/amd64"}
}

func startAcq(t *testing.T, a *Acquirer) {
	t.Helper()
	c, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { _ = a.Start(c); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
}

func syftBytes(t *testing.T, user string) []byte {
	t.Helper()
	doc := fixtureSBOM("syft")
	if user != "" {
		doc.Source = source.Description{Name: "app", Metadata: source.ImageMetadata{UserInput: "app",
			RawConfig: []byte(fmt.Sprintf(`{"config":{"User":%q}}`, user))}}
	}
	b, err := EncodeSyftJSON(doc)
	require.NoError(t, err)
	return b
}

func getImg(t *testing.T, st *store.Store, d string) model.Image {
	t.Helper()
	img, ok, err := st.GetImage(ctx, d)
	require.NoError(t, err)
	require.True(t, ok)
	return img
}

func TestAcquirer_QuarantineAfterTwoFailures(t *testing.T) {
	st, clock := acqStore(t), acqClock()
	var afterFirst model.Image
	src := &fakeSource{name: "registry"}
	src.script = func(ctx context.Context, n int, r Request) (*Result, error) {
		if n == 2 {
			afterFirst = getImg(t, st, acqDigest) // state left by the first failure
		}
		return nil, errors.New("cataloguer crashed")
	}
	a := NewAcquirer(AcquirerOptions{Store: st, Sources: []Source{src}, Concurrency: 1, Now: clock.Now, RetryAfter: 10 * time.Millisecond})
	startAcq(t, a)
	r := acqReq()
	a.Enqueue(r)
	require.Eventually(t, func() bool {
		img, ok, _ := st.GetImage(ctx, acqDigest)
		return ok && img.Status == model.ImageCatalogFailed
	}, 5*time.Second, 5*time.Millisecond)
	require.EqualValues(t, 2, src.calls.Load())
	require.Equal(t, model.ImagePending, afterFirst.Status)
	require.Equal(t, 1, afterFirst.Attempts)
	img := getImg(t, st, acqDigest)
	require.Equal(t, 2, img.Attempts)
	require.True(t, img.QuarantinedUntil.Equal(clock.Now().Add(24*time.Hour)))
	require.True(t, strings.Contains(img.StatusReason, "cataloguer crashed"))

	a.Enqueue(r)
	time.Sleep(50 * time.Millisecond)
	require.EqualValues(t, 2, src.calls.Load())
	_, err := a.AcquireNow(ctx, r)
	require.True(t, errors.Is(err, ErrQuarantined))
	require.EqualValues(t, 2, src.calls.Load())

	clock.Advance(24*time.Hour + time.Second)
	a.Enqueue(r)
	require.Eventually(t, func() bool { return src.calls.Load() == 3 }, 5*time.Second, 5*time.Millisecond)
	// attempts stay at 2+, so one more failure re-quarantines immediately
	require.Eventually(t, func() bool {
		img := getImg(t, st, acqDigest)
		return img.Attempts == 3 && img.QuarantinedUntil.After(clock.Now())
	}, 5*time.Second, 5*time.Millisecond)
	require.EqualValues(t, 3, src.calls.Load())
}

func TestAcquirer_ChainFallsThroughOnNotFound(t *testing.T) {
	st, clock := acqStore(t), acqClock()
	r := acqReq()
	require.NoError(t, st.UpsertImage(ctx, model.Image{Digest: acqDigest, Repo: r.Repo, Platform: r.Platform,
		Status: model.ImagePending, VersionAnnotation: "1.27.0"}))

	att := &fakeSource{name: "attestation", err: ErrNotFound}
	cat := &fakeSource{name: "registry", res: &Result{SyftJSON: syftBytes(t, "1000"), Source: "registry"}}
	var calls []string
	var mu sync.Mutex
	a := NewAcquirer(AcquirerOptions{Store: st, Sources: []Source{att, cat}, Concurrency: 1, Now: clock.Now,
		OnCatalogued: func(_ context.Context, d string) error {
			mu.Lock()
			calls = append(calls, d)
			mu.Unlock()
			return nil
		}})
	startAcq(t, a)
	res, err := a.AcquireNow(ctx, r)
	require.NoError(t, err)
	require.NotEmpty(t, res.Packages)
	require.EqualValues(t, 1, att.calls.Load())
	require.EqualValues(t, 1, cat.calls.Load())

	pkgs, err := st.PackagesForImage(ctx, acqDigest)
	require.NoError(t, err)
	require.NotEmpty(t, pkgs)
	_, ok, err := st.GetSBOM(ctx, acqDigest)
	require.NoError(t, err)
	require.True(t, ok)
	img := getImg(t, st, acqDigest)
	require.Equal(t, model.ImageCatalogued, img.Status)
	require.Equal(t, "registry", img.Source)
	require.True(t, img.CataloguedAt.Equal(clock.Now()))
	require.Equal(t, 0, img.Attempts)
	require.Equal(t, "sha256:index", img.IndexDigest)
	require.Equal(t, "1000", img.ConfigUser)
	require.Equal(t, "1.27.0", img.VersionAnnotation)
	mu.Lock()
	require.Equal(t, []string{acqDigest}, calls)
	mu.Unlock()
}

func TestAcquirer_AttestationWinsAndSkipsCatalog(t *testing.T) {
	st, clock := acqStore(t), acqClock()
	att := &fakeSource{name: "attestation", res: &Result{SyftJSON: syftBytes(t, "1000"), Source: "attestation",
		ConfigUser: "65532", VersionAnnotation: "2.0",
		Coverage: model.Coverage{Notes: []string{AttestationCoverageNote}}}}
	cat := &fakeSource{name: "registry", err: errors.New("must not be called")}
	a := NewAcquirer(AcquirerOptions{Store: st, Sources: []Source{att, cat}, Concurrency: 1, Now: clock.Now})
	startAcq(t, a)
	res, err := a.AcquireNow(ctx, acqReq())
	require.NoError(t, err)
	require.EqualValues(t, 0, cat.calls.Load())
	require.Contains(t, res.Coverage.Notes, AttestationCoverageNote)
	img := getImg(t, st, acqDigest)
	require.Equal(t, "65532", img.ConfigUser)
	require.Equal(t, "attestation", img.Source)
	require.Equal(t, "2.0", img.VersionAnnotation)
	require.Contains(t, img.Coverage.Notes, AttestationCoverageNote)
}

func TestAcquirer_UnauthorizedMarksUnresolvable(t *testing.T) {
	st, clock := acqStore(t), acqClock()
	r := acqReq()
	reason := fmt.Sprintf(registry.ReasonUnauthorized, r.Repo)
	src := &fakeSource{name: "registry", err: &AcquireError{Kind: FailUnresolvable, Reason: reason}}
	var hook atomic.Int32
	a := NewAcquirer(AcquirerOptions{Store: st, Sources: []Source{src}, Concurrency: 1, Now: clock.Now,
		OnCatalogued: func(context.Context, string) error { hook.Add(1); return nil }})
	startAcq(t, a)
	_, err := a.AcquireNow(ctx, r)
	require.Error(t, err)
	img := getImg(t, st, acqDigest)
	require.Equal(t, model.ImageUnresolvable, img.Status)
	require.Equal(t, reason, img.StatusReason)
	require.True(t, img.QuarantinedUntil.Equal(clock.Now().Add(6*time.Hour)))
	require.Equal(t, 0, img.Attempts)
	require.EqualValues(t, 0, hook.Load())
}

func TestAcquirer_TooLargeQuarantinedImmediately(t *testing.T) {
	st, clock := acqStore(t), acqClock()
	src := &fakeSource{name: "registry", err: &AcquireError{Kind: FailQuarantine, Reason: "image exceeds the size limit"}}
	a := NewAcquirer(AcquirerOptions{Store: st, Sources: []Source{src}, Concurrency: 1, Now: clock.Now, RetryAfter: 10 * time.Millisecond})
	startAcq(t, a)
	a.Enqueue(acqReq())
	require.Eventually(t, func() bool {
		img, ok, _ := st.GetImage(ctx, acqDigest)
		return ok && img.Status == model.ImageCatalogFailed
	}, 5*time.Second, 5*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	require.EqualValues(t, 1, src.calls.Load())
	img := getImg(t, st, acqDigest)
	require.True(t, img.QuarantinedUntil.Equal(clock.Now().Add(24*time.Hour)))
	require.Equal(t, "image exceeds the size limit", img.StatusReason)
}

func TestAcquirer_TransientNotCounted(t *testing.T) {
	st, clock := acqStore(t), acqClock()
	good := syftBytes(t, "")
	src := &fakeSource{name: "registry"}
	src.script = func(ctx context.Context, n int, r Request) (*Result, error) {
		if n <= 3 {
			require.Equal(t, 0, getImgOrZero(st, acqDigest).Attempts)
			return nil, &AcquireError{Kind: FailTransient, Reason: "cataloguer busy"}
		}
		return &Result{SyftJSON: good, Source: "registry"}, nil
	}
	a := NewAcquirer(AcquirerOptions{Store: st, Sources: []Source{src}, Concurrency: 1, Now: clock.Now, RetryAfter: 10 * time.Millisecond})
	startAcq(t, a)
	a.Enqueue(acqReq())
	require.Eventually(t, func() bool {
		img, ok, _ := st.GetImage(ctx, acqDigest)
		return ok && img.Status == model.ImageCatalogued
	}, 5*time.Second, 5*time.Millisecond)
	require.EqualValues(t, 4, src.calls.Load())
	require.Equal(t, 0, getImg(t, st, acqDigest).Attempts)
}

func getImgOrZero(st *store.Store, d string) model.Image {
	img, _, _ := st.GetImage(ctx, d)
	return img
}

func TestAcquirer_TransientNotCountedOnCancel(t *testing.T) {
	st, clock := acqStore(t), acqClock()
	r := acqReq()
	require.NoError(t, st.UpsertImage(ctx, model.Image{Digest: acqDigest, Repo: r.Repo, Platform: r.Platform, Status: model.ImagePending}))
	entered := make(chan struct{})
	src := &fakeSource{name: "registry"}
	src.script = func(ctx context.Context, n int, r Request) (*Result, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	a := NewAcquirer(AcquirerOptions{Store: st, Sources: []Source{src}, Concurrency: 1, Now: clock.Now, RetryAfter: 10 * time.Millisecond})
	c, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { _ = a.Start(c); close(done) }()
	a.Enqueue(r)
	<-entered
	cancel()
	<-done
	img := getImg(t, st, acqDigest)
	require.Equal(t, 0, img.Attempts)
	require.Equal(t, model.ImagePending, img.Status)
	require.EqualValues(t, 1, src.calls.Load())
}

func TestAcquirer_SingleflightDedup(t *testing.T) {
	st, clock := acqStore(t), acqClock()
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	good := syftBytes(t, "")
	src := &fakeSource{name: "registry"}
	src.script = func(ctx context.Context, n int, r Request) (*Result, error) {
		entered <- struct{}{}
		<-release
		return &Result{SyftJSON: good, Source: "registry"}, nil
	}
	a := NewAcquirer(AcquirerOptions{Store: st, Sources: []Source{src}, Concurrency: 4, Now: clock.Now})
	startAcq(t, a)
	r := acqReq()
	a.Enqueue(r)
	<-entered
	for i := 0; i < 100; i++ {
		a.Enqueue(r)
	}
	var wg sync.WaitGroup
	results := make([]*Result, 5)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := a.AcquireNow(ctx, r)
			require.NoError(t, err)
			results[i] = res
		}()
	}
	require.Eventually(t, func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		return len(a.jobs[acqDigest].waiters) == 5
	}, 5*time.Second, 5*time.Millisecond)
	close(release)
	wg.Wait()
	require.EqualValues(t, 1, src.calls.Load())
	for _, res := range results {
		require.Same(t, results[0], res)
	}

	// already catalogued: Enqueue does nothing, AcquireNow rebuilds from the store
	a.Enqueue(r)
	res, err := a.AcquireNow(ctx, r)
	require.NoError(t, err)
	require.EqualValues(t, 1, src.calls.Load())
	require.NotEmpty(t, res.Packages)
	require.Equal(t, good, res.SyftJSON)
}

func TestAcquirer_AcquireNowAfterInventory(t *testing.T) {
	st, clock := acqStore(t), acqClock()
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	var mu sync.Mutex
	var order []string
	good := syftBytes(t, "")
	src := &fakeSource{name: "registry"}
	src.script = func(ctx context.Context, n int, r Request) (*Result, error) {
		mu.Lock()
		order = append(order, r.Digest)
		mu.Unlock()
		if r.Digest == "sha256:A" {
			entered <- struct{}{}
			<-release
		}
		return &Result{SyftJSON: good, Source: "registry"}, nil
	}
	a := NewAcquirer(AcquirerOptions{Store: st, Sources: []Source{src}, Concurrency: 1, Now: clock.Now})
	startAcq(t, a)
	req := func(d string) Request {
		return Request{Repo: "docker.io/library/x", Digest: d, Platform: "linux/amd64"}
	}
	a.Enqueue(req("sha256:A"))
	<-entered
	a.Enqueue(req("sha256:B"))
	done := make(chan error, 1)
	go func() { _, err := a.AcquireNow(ctx, req("sha256:C")); done <- err }()
	require.Eventually(t, func() bool { return a.Stats().Queued == 2 }, 5*time.Second, 5*time.Millisecond)
	close(release)
	require.NoError(t, <-done)
	mu.Lock()
	require.Equal(t, []string{"sha256:A", "sha256:B", "sha256:C"}, order)
	mu.Unlock()
}
