package sbom

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
	"golang.org/x/sync/singleflight"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/output/metrics"
	"github.com/the-it-dept/ffs/internal/store"
)

// ErrQuarantined means the digest is quarantined and was not attempted.
var ErrQuarantined = errors.New("sbom: digest quarantined")

const (
	defaultRetryAfter        = time.Minute
	defaultQuarantineFor     = 24 * time.Hour
	defaultUnresolvableRetry = 6 * time.Hour
	countedFailureLimit      = 2
	sweepInterval            = time.Hour
	onCataloguedTries        = 3
)

// onCataloguedDelay is the pause between OnCatalogued attempts.
var onCataloguedDelay = 5 * time.Second

// AcquirerOptions configures an Acquirer.
type AcquirerOptions struct {
	Store             *store.Store
	Sources           []Source                                       // ordered: attestation, then catalog
	Concurrency       int                                            // config Catalog.Concurrency
	OnCatalogued      func(ctx context.Context, digest string) error // called after an SBOM is stored
	Now               func() time.Time
	RetryAfter        time.Duration // delay before the second counted attempt and for transient requeues; default 1m
	QuarantineFor     time.Duration // default 24h
	UnresolvableRetry time.Duration // default 6h
	Log               logr.Logger
}

// AcquirerStats is a snapshot for metrics.
type AcquirerStats struct {
	Queued, InFlight                int
	Catalogued, Failed, Quarantined uint64
}

type outcome struct {
	res *Result
	err error
}

// job is one digest's queued or running acquisition and the AcquireNow callers waiting on it.
type job struct {
	req     Request
	waiters []chan outcome
}

// Acquirer orders, deduplicates and bounds SBOM acquisition and applies the quarantine policy.
type Acquirer struct {
	o  AcquirerOptions
	sf singleflight.Group

	mu       sync.Mutex
	cond     *sync.Cond
	high     []*job // inventory work
	low      []*job // AcquireNow work
	jobs     map[string]*job
	inFlight int
	lastReq  map[string]Request
	stopped  bool

	catalogued, failed, quarantined atomic.Uint64
}

// NewAcquirer builds an Acquirer, filling option defaults.
func NewAcquirer(o AcquirerOptions) *Acquirer {
	if o.Concurrency < 1 {
		o.Concurrency = 2
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.RetryAfter <= 0 {
		o.RetryAfter = defaultRetryAfter
	}
	if o.QuarantineFor <= 0 {
		o.QuarantineFor = defaultQuarantineFor
	}
	if o.UnresolvableRetry <= 0 {
		o.UnresolvableRetry = defaultUnresolvableRetry
	}
	a := &Acquirer{o: o, jobs: map[string]*job{}, lastReq: map[string]Request{}}
	a.cond = sync.NewCond(&a.mu)
	return a
}

// Enqueue queues r for acquisition without blocking; a digest already queued or running is not queued again.
func (a *Acquirer) Enqueue(r Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lastReq[r.Digest] = r
	if _, ok := a.jobs[r.Digest]; ok {
		return
	}
	j := &job{req: r}
	a.jobs[r.Digest] = j
	a.high = append(a.high, j)
	metrics.CatalogQueueDepth.Set(float64(len(a.high) + len(a.low)))
	a.cond.Signal()
}

// AcquireNow acquires r's SBOM and waits for the result. It queues behind inventory work and joins an
// acquisition already queued or running for the same digest.
func (a *Acquirer) AcquireNow(ctx context.Context, r Request) (*Result, error) {
	ch := make(chan outcome, 1)
	a.mu.Lock()
	a.lastReq[r.Digest] = r
	j, ok := a.jobs[r.Digest]
	if !ok {
		j = &job{req: r}
		a.jobs[r.Digest] = j
		a.low = append(a.low, j)
		metrics.CatalogQueueDepth.Set(float64(len(a.high) + len(a.low)))
		a.cond.Signal()
	}
	j.waiters = append(j.waiters, ch)
	a.mu.Unlock()
	select {
	case out := <-ch:
		return out.res, out.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// NeedLeaderElection reports that acquisition runs on the leader only.
func (a *Acquirer) NeedLeaderElection() bool { return true }

// Stats returns a snapshot of queue depth and outcome counters.
func (a *Acquirer) Stats() AcquirerStats {
	a.mu.Lock()
	queued, inFlight := len(a.high)+len(a.low), a.inFlight
	a.mu.Unlock()
	return AcquirerStats{Queued: queued, InFlight: inFlight, Catalogued: a.catalogued.Load(),
		Failed: a.failed.Load(), Quarantined: a.quarantined.Load()}
}

// Start runs the workers and the hourly sweep until ctx is done.
func (a *Acquirer) Start(ctx context.Context) error {
	var wg sync.WaitGroup
	for i := 0; i < a.o.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.worker(ctx)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(sweepInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				a.sweep(ctx)
			}
		}
	}()
	go func() {
		<-ctx.Done()
		a.mu.Lock()
		a.stopped = true
		a.cond.Broadcast()
		a.mu.Unlock()
	}()
	<-ctx.Done()
	wg.Wait()
	return nil
}

func (a *Acquirer) next() *job {
	a.mu.Lock()
	defer a.mu.Unlock()
	for len(a.high) == 0 && len(a.low) == 0 && !a.stopped {
		a.cond.Wait()
	}
	if a.stopped {
		return nil
	}
	var j *job
	if len(a.high) > 0 {
		j, a.high = a.high[0], a.high[1:]
	} else {
		j, a.low = a.low[0], a.low[1:]
	}
	a.inFlight++
	metrics.CatalogQueueDepth.Set(float64(len(a.high) + len(a.low)))
	return j
}

func (a *Acquirer) worker(ctx context.Context) {
	for {
		j := a.next()
		if j == nil {
			return
		}
		v, _, _ := a.sf.Do(j.req.Digest, func() (any, error) {
			res, requeue, err := a.process(ctx, j.req)
			return processed{res, requeue, err}, nil
		})
		p := v.(processed)
		a.mu.Lock()
		a.inFlight--
		delete(a.jobs, j.req.Digest)
		waiters := j.waiters
		a.mu.Unlock()
		for _, w := range waiters {
			w <- outcome{p.res, p.err}
		}
		if p.requeue && ctx.Err() == nil {
			req := j.req
			time.AfterFunc(a.o.RetryAfter, func() {
				if ctx.Err() == nil {
					a.Enqueue(req)
				}
			})
		}
	}
}

type processed struct {
	res     *Result
	requeue bool
	err     error
}

// sweep re-enqueues known digests whose quarantine has expired.
func (a *Acquirer) sweep(ctx context.Context) {
	a.mu.Lock()
	reqs := make([]Request, 0, len(a.lastReq))
	for _, r := range a.lastReq {
		reqs = append(reqs, r)
	}
	a.mu.Unlock()
	now := a.o.Now()
	for _, r := range reqs {
		img, ok, err := a.o.Store.GetImage(ctx, r.Digest)
		if err != nil || !ok || img.QuarantinedUntil.IsZero() || now.Before(img.QuarantinedUntil) {
			continue
		}
		if img.Status == model.ImageCatalogFailed || img.Status == model.ImageUnresolvable {
			a.Enqueue(r)
		}
	}
}

// process runs one attempt for r. It returns the result on success, otherwise the error and whether
// the digest should be retried after RetryAfter.
func (a *Acquirer) process(ctx context.Context, r Request) (*Result, bool, error) {
	st := a.o.Store
	img, ok, err := st.GetImage(ctx, r.Digest)
	if err != nil {
		return nil, ctx.Err() == nil, err
	}
	now := a.o.Now()
	if ok {
		switch {
		case img.Status == model.ImageCatalogued:
			res, err := a.fromStore(ctx, img)
			return res, false, err
		case (img.Status == model.ImageCatalogFailed || img.Status == model.ImageUnresolvable) && now.Before(img.QuarantinedUntil):
			return nil, false, ErrQuarantined
		}
	}

	var res *Result
	err = nil
	for _, src := range a.o.Sources {
		res, err = src.Acquire(ctx, r)
		if errors.Is(err, ErrNotFound) {
			res, err = nil, nil
			continue
		}
		break
	}
	if err == nil && res == nil {
		err = &AcquireError{Kind: FailCounted, Reason: "no SBOM source produced an inventory"}
	}
	if err == nil {
		res, err = a.store(ctx, img, r, res)
		if err == nil {
			return res, false, nil
		}
	}
	return nil, a.fail(ctx, img, r, err), err
}

// store persists a successful result and notifies OnCatalogued.
func (a *Acquirer) store(ctx context.Context, prev model.Image, r Request, res *Result) (*Result, error) {
	doc, err := DecodeSyftJSON(res.SyftJSON)
	if err != nil {
		return nil, &AcquireError{Kind: FailCounted, Reason: "decoding SBOM", Err: err}
	}
	pkgs, cov := Normalize(r.Digest, doc)
	for _, n := range res.Coverage.Notes {
		if !slices.Contains(cov.Notes, n) {
			cov.Notes = append(cov.Notes, n)
		}
	}
	out := *res
	out.Packages, out.Coverage = pkgs, cov
	if out.ConfigUser == "" {
		out.ConfigUser = ConfigUser(doc)
	}
	if err := a.o.Store.PutSBOM(ctx, r.Digest, out.SyftJSON, pkgs); err != nil {
		return nil, a.storeErr(ctx, err)
	}
	img := a.base(prev, r)
	img.Status, img.StatusReason = model.ImageCatalogued, ""
	img.Source, img.ConfigUser, img.Coverage = out.Source, out.ConfigUser, cov
	if out.VersionAnnotation != "" {
		img.VersionAnnotation = out.VersionAnnotation
	}
	img.CataloguedAt, img.Attempts, img.QuarantinedUntil = a.o.Now(), 0, time.Time{}
	if err := a.o.Store.UpsertImage(ctx, img); err != nil {
		return nil, a.storeErr(ctx, err)
	}
	a.catalogued.Add(1)
	a.notify(ctx, r.Digest)
	return &out, nil
}

// storeErr marks store failures during shutdown as transient.
func (a *Acquirer) storeErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return &AcquireError{Kind: FailTransient, Err: err}
	}
	return err
}

func (a *Acquirer) notify(ctx context.Context, digest string) {
	if a.o.OnCatalogued == nil {
		return
	}
	var err error
	for i := 0; i < onCataloguedTries; i++ {
		if err = a.o.OnCatalogued(ctx, digest); err == nil {
			return
		}
		if i < onCataloguedTries-1 {
			select {
			case <-ctx.Done():
				i = onCataloguedTries
			case <-time.After(onCataloguedDelay):
			}
		}
	}
	a.o.Log.Error(err, "image catalogued hook failed", "digest", digest)
}

// base returns the stored row merged with the request's identity fields.
func (a *Acquirer) base(prev model.Image, r Request) model.Image {
	img := prev
	img.Digest = r.Digest
	if r.IndexDigest != "" {
		img.IndexDigest = r.IndexDigest
	}
	if r.Repo != "" {
		img.Repo = r.Repo
	}
	if r.Platform != "" {
		img.Platform = r.Platform
	}
	return img
}

// fail records a failed attempt and reports whether the digest should be retried after RetryAfter.
func (a *Acquirer) fail(ctx context.Context, prev model.Image, r Request, err error) bool {
	kind := KindOf(err)
	if ctx.Err() != nil {
		kind = FailTransient
	}
	reason := err.Error()
	var ae *AcquireError
	if errors.As(err, &ae) && ae.Reason != "" {
		reason = ae.Reason
	}
	now := a.o.Now()
	img := a.base(prev, r)
	if img.Status == "" {
		img.Status = model.ImagePending
	}
	requeue := false
	switch kind {
	case FailTransient:
		return ctx.Err() == nil
	case FailUnresolvable:
		img.Status, img.StatusReason = model.ImageUnresolvable, reason
		img.QuarantinedUntil = now.Add(a.o.UnresolvableRetry)
		a.quarantined.Add(1)
	case FailQuarantine:
		img.Status, img.StatusReason = model.ImageCatalogFailed, reason
		img.Attempts++
		img.QuarantinedUntil = now.Add(a.o.QuarantineFor)
		a.quarantined.Add(1)
	default:
		img.Attempts++
		if img.Attempts >= countedFailureLimit {
			img.Status, img.StatusReason = model.ImageCatalogFailed, reason
			img.QuarantinedUntil = now.Add(a.o.QuarantineFor)
			a.quarantined.Add(1)
		} else {
			img.Status, img.StatusReason = model.ImagePending, ""
			requeue = true
		}
	}
	a.failed.Add(1)
	metrics.CatalogFailures.Inc()
	if uerr := a.o.Store.UpsertImage(ctx, img); uerr != nil {
		a.o.Log.Error(uerr, "recording acquisition failure", "digest", r.Digest)
	}
	a.o.Log.Info("sbom acquisition failed", "digest", r.Digest, "kind", fmt.Sprint(kind), "reason", reason)
	return requeue
}

// fromStore rebuilds a Result for an already catalogued image.
func (a *Acquirer) fromStore(ctx context.Context, img model.Image) (*Result, error) {
	pkgs, err := a.o.Store.PackagesForImage(ctx, img.Digest)
	if err != nil {
		return nil, err
	}
	b, _, err := a.o.Store.GetSBOM(ctx, img.Digest)
	if err != nil {
		return nil, err
	}
	return &Result{SyftJSON: b, Packages: pkgs, Coverage: img.Coverage, Source: img.Source,
		VersionAnnotation: img.VersionAnnotation, ConfigUser: img.ConfigUser}, nil
}
