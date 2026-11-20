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
	"golang.org/x/sync/semaphore"
	"golang.org/x/sync/singleflight"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/output/metrics"
	"github.com/the-it-dept/ffs/internal/registry"
	"github.com/the-it-dept/ffs/internal/store"
)

// ErrQuarantined means the digest is quarantined and was not attempted.
var ErrQuarantined = errors.New("sbom: digest quarantined")

const (
	defaultRetryAfter        = time.Minute
	defaultQuarantineFor     = 24 * time.Hour
	defaultUnresolvableRetry = 6 * time.Hour
	defaultJobTimeout        = 30 * time.Minute
	defaultMatchTimeout      = 30 * time.Minute
	countedFailureLimit      = 2
	sweepInterval            = time.Hour
	onCataloguedTries        = 3
	// matchAttemptLimit is how many match runs a catalogued image gets. An image whose matching keeps
	// failing, or keeps stopping the controller, is then quarantined instead of retried at every start.
	matchAttemptLimit = 3
	// maxTransientDelay caps the backoff of an image that keeps failing transiently.
	maxTransientDelay = 30 * time.Minute
	// maxAltCreds bounds how many other owners' credentials are tried after a registry refusal.
	maxAltCreds = 4
	// bookkeepingTimeout bounds the store writes that must happen even while shutting down.
	bookkeepingTimeout = 5 * time.Second
)

const (
	reasonControllerStopped = "the controller stopped while processing the image"
	reasonMatchFailed       = "matching the image did not complete"
	reasonJobTimeout        = "acquisition did not finish within %s"
	reasonSBOMTooLarge      = "SBOM of %d bytes is larger than the %d byte limit"
)

// onCataloguedDelay is the pause between OnCatalogued attempts.
var onCataloguedDelay = 5 * time.Second

// AcquirerOptions configures an Acquirer.
type AcquirerOptions struct {
	Store   *store.Store
	Sources []Source // ordered; a source answering ErrNotFound hands over to the next
	// Fallback is tried when the sources end in a quarantine (an image too large to catalogue): an
	// SBOM it finds is used rather than leaving the image without one. nil: no fallback.
	Fallback          Source
	Concurrency       int                                            // config Catalog.Concurrency
	OnCatalogued      func(ctx context.Context, digest string) error // called after an SBOM is stored
	Now               func() time.Time
	RetryAfter        time.Duration // delay before the second counted attempt and the first transient requeue; default 1m
	QuarantineFor     time.Duration // default 24h
	UnresolvableRetry time.Duration // default 6h
	JobTimeout        time.Duration // bounds the source calls of one attempt; default 30m
	MatchTimeout      time.Duration // bounds one OnCatalogued run; default 30m
	Log               logr.Logger
}

// AcquirerStats is a snapshot for metrics and readiness. Retrying counts the images waiting out the
// delay before their next attempt, which are neither queued nor in flight meanwhile.
type AcquirerStats struct {
	Queued, InFlight, Retrying      int
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
	// solo jobs start only when nothing else is in flight, and nothing starts while they run.
	solo bool
	// overlapped is set when another job ran at any time while this one did.
	overlapped bool
}

// Acquirer orders, deduplicates and bounds SBOM acquisition and applies the quarantine policy.
//
// Every acquisition runs under registry.LowPriority, so cataloguing never takes the last of a
// registry's budget from inventory resolution. Images whose quarantine has ended are handed back by
// the inventory, which re-reads them from the store, so retries survive a restart. Acquisitions in
// progress and catalogued images not yet matched are recorded in the store too: an attempt the
// controller did not live through counts against the image, and a match it did not finish runs
// again at the next start.
type Acquirer struct {
	o      AcquirerOptions
	sf     singleflight.Group
	decode *semaphore.Weighted // bounds the SBOM bytes decoded at once

	mu        sync.Mutex
	cond      *sync.Cond
	high      []*job // inventory work
	low       []*job // AcquireNow work
	jobs      map[string]*job
	running   map[*job]struct{}
	inFlight  int
	retrying  int             // retries scheduled but not yet queued
	solo      map[string]bool // digests whose next attempt runs alone
	soloBusy  bool            // a solo job is running
	transient map[string]int  // consecutive transient failures per digest
	stopped   bool

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
	if o.JobTimeout <= 0 {
		o.JobTimeout = defaultJobTimeout
	}
	if o.MatchTimeout <= 0 {
		o.MatchTimeout = defaultMatchTimeout
	}
	a := &Acquirer{o: o, decode: semaphore.NewWeighted(MaxSBOMBytes), jobs: map[string]*job{},
		running: map[*job]struct{}{}, solo: map[string]bool{}, transient: map[string]int{}}
	a.cond = sync.NewCond(&a.mu)
	return a
}

// Enqueue queues r for acquisition without blocking; a digest already queued or running is not queued again.
func (a *Acquirer) Enqueue(r Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enqueue(r)
}

// enqueue is Enqueue; the caller holds mu.
func (a *Acquirer) enqueue(r Request) {
	if _, ok := a.jobs[r.Digest]; ok {
		return
	}
	j := &job{req: r, solo: a.solo[r.Digest]}
	a.jobs[r.Digest] = j
	a.high = append(a.high, j)
	metrics.CatalogQueueDepth.Set(float64(len(a.high) + len(a.low)))
	a.cond.Broadcast()
}

// AcquireNow acquires r's SBOM and waits for the result. It queues behind inventory work and joins an
// acquisition already queued or running for the same digest.
func (a *Acquirer) AcquireNow(ctx context.Context, r Request) (*Result, error) {
	ch := make(chan outcome, 1)
	a.mu.Lock()
	j, ok := a.jobs[r.Digest]
	if !ok {
		j = &job{req: r, solo: a.solo[r.Digest]}
		a.jobs[r.Digest] = j
		a.low = append(a.low, j)
		metrics.CatalogQueueDepth.Set(float64(len(a.high) + len(a.low)))
		a.cond.Broadcast()
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
	queued, inFlight, retrying := len(a.high)+len(a.low), a.inFlight, a.retrying
	a.mu.Unlock()
	return AcquirerStats{Queued: queued, InFlight: inFlight, Retrying: retrying, Catalogued: a.catalogued.Load(),
		Failed: a.failed.Load(), Quarantined: a.quarantined.Load()}
}

// Start runs the workers until ctx is done. At start and then hourly it matches again the
// catalogued images whose match did not complete.
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
		a.rematch(ctx)
		t := time.NewTicker(sweepInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				a.rematch(ctx)
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

// next waits for a job that may start and marks it running: inventory work first; a solo job only
// once nothing else is in flight, and nothing while a solo job runs.
func (a *Acquirer) next() *job {
	a.mu.Lock()
	defer a.mu.Unlock()
	for {
		if a.stopped {
			return nil
		}
		if j := a.pick(); j != nil {
			a.inFlight++
			a.soloBusy = j.solo
			for r := range a.running {
				r.overlapped = true
			}
			j.overlapped = len(a.running) > 0
			a.running[j] = struct{}{}
			metrics.CatalogQueueDepth.Set(float64(len(a.high) + len(a.low)))
			return j
		}
		a.cond.Wait()
	}
}

// pick pops the job to start now, or returns nil when none may start yet.
func (a *Acquirer) pick() *job {
	if a.soloBusy {
		return nil
	}
	for _, q := range []*[]*job{&a.high, &a.low} {
		if len(*q) == 0 {
			continue
		}
		j := (*q)[0]
		if j.solo && a.inFlight > 0 {
			return nil // it starts next, once the jobs in flight are done
		}
		*q = (*q)[1:]
		return j
	}
	return nil
}

func (a *Acquirer) worker(ctx context.Context) {
	for {
		j := a.next()
		if j == nil {
			return
		}
		v, _, _ := a.sf.Do(j.req.Digest, func() (any, error) {
			res, retry, err := a.process(ctx, j)
			return processed{res, retry, err}, nil
		})
		p := v.(processed)
		retry := p.retry > 0 && ctx.Err() == nil
		a.mu.Lock()
		a.inFlight--
		if retry {
			a.retrying++ // in the same step, so Stats never sees the image neither in flight nor waiting
		}
		delete(a.running, j)
		if j.solo {
			a.soloBusy = false
			delete(a.solo, j.req.Digest)
		}
		delete(a.jobs, j.req.Digest)
		waiters := j.waiters
		a.cond.Broadcast()
		a.mu.Unlock()
		for _, w := range waiters {
			w <- outcome{p.res, p.err}
		}
		if retry {
			req := j.req
			time.AfterFunc(p.retry, func() {
				a.mu.Lock()
				defer a.mu.Unlock()
				a.retrying--
				if ctx.Err() == nil {
					a.enqueue(req)
				}
			})
		}
	}
}

type processed struct {
	res   *Result
	retry time.Duration // > 0: enqueue the digest again after this long
	err   error
}

// process runs one attempt for j. It returns the result on success, otherwise the error and how
// long to wait before retrying the digest (0: no retry).
func (a *Acquirer) process(ctx context.Context, j *job) (*Result, time.Duration, error) {
	r := j.req
	st := a.o.Store
	img, ok, err := st.GetImage(ctx, r.Digest)
	if err != nil {
		return nil, a.transientDelay(ctx, r.Digest), err
	}
	now := a.o.Now()
	if ok {
		switch {
		case img.Status == model.ImageCatalogued:
			res, err := a.fromStore(ctx, img)
			return res, 0, err
		case (img.Status == model.ImageCatalogFailed || img.Status == model.ImageUnresolvable) && now.Before(img.QuarantinedUntil):
			return nil, 0, ErrQuarantined
		}
	}

	stale, err := st.BeginAcquire(ctx, r.Digest, now)
	if err != nil {
		return nil, a.transientDelay(ctx, r.Digest), err
	}
	defer a.bookkeep(ctx, "ending acquisition record", r.Digest, st.EndAcquire)
	if stale {
		// The process that ran the previous attempt stopped during it (killed while decoding a huge
		// SBOM, say): that counts like a crash of the cataloguer, so an image cannot crash-loop ffs.
		img = a.base(img, r)
		img.Attempts++
		if img.Attempts >= countedFailureLimit {
			a.quarantine(ctx, img, reasonControllerStopped)
			return nil, 0, &AcquireError{Kind: FailQuarantine, Reason: reasonControllerStopped}
		}
		if img.Status == "" {
			img.Status = model.ImagePending
		}
		a.upsert(ctx, img)
	}

	jctx, cancel := context.WithTimeout(registry.LowPriority(ctx), a.o.JobTimeout)
	defer cancel()
	res, err := a.acquire(jctx, r)
	if err != nil && ctx.Err() == nil && jctx.Err() != nil {
		// The job's own deadline, not shutdown: the registry or the cataloguer stalled. Not the image's fault.
		err = &AcquireError{Kind: FailTransient, Reason: fmt.Sprintf(reasonJobTimeout, a.o.JobTimeout), Err: err}
	}
	if err == nil {
		res, err = a.store(ctx, img, r, res)
		if err == nil {
			a.resetTransient(r.Digest)
			a.match(ctx, r.Digest)
			return res, 0, nil
		}
	}
	return nil, a.fail(ctx, j, img, r, err), err
}

// acquire runs the sources for r. After a registry refusal it runs them again with the credentials
// of the other owners of the image, and after a quarantine it tries the fallback.
func (a *Acquirer) acquire(ctx context.Context, r Request) (*Result, error) {
	res, err := a.runSources(ctx, r)
	if err != nil && KindOf(err) == FailUnresolvable {
		for _, cs := range a.altCreds(ctx, r) {
			alt := r
			alt.Creds = cs
			ares, aerr := a.runSources(ctx, alt)
			if aerr == nil || KindOf(aerr) != FailUnresolvable {
				return ares, aerr
			}
		}
	}
	if err != nil && KindOf(err) == FailQuarantine && a.o.Fallback != nil {
		fres, ferr := a.o.Fallback.Acquire(ctx, r)
		switch {
		case ferr == nil && fres != nil:
			return fres, nil
		case ferr != nil && !errors.Is(ferr, ErrNotFound) && KindOf(ferr) == FailTransient:
			return nil, ferr
		}
	}
	return res, err
}

// runSources tries the sources in order; ErrNotFound hands over to the next one.
func (a *Acquirer) runSources(ctx context.Context, r Request) (*Result, error) {
	for _, src := range a.o.Sources {
		res, err := src.Acquire(ctx, r)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err == nil && res == nil {
			continue
		}
		return res, err
	}
	return nil, &AcquireError{Kind: FailCounted, Reason: "no SBOM source produced an inventory"}
}

// altCreds returns the distinct credentials of the other workloads that run r's image, at most
// maxAltCreds: one namespace's pull secret may have expired while another's still works.
func (a *Acquirer) altCreds(ctx context.Context, r Request) []registry.CredSet {
	keys, err := a.o.Store.OwnersForDigests(ctx, []string{r.Digest})
	if err != nil {
		a.o.Log.Error(err, "listing the owners of an image for other pull credentials", "digest", r.Digest)
		return nil
	}
	seen := map[string]bool{r.Creds.Key(): true}
	var out []registry.CredSet
	for _, k := range keys {
		o, ok, err := a.o.Store.GetOwner(ctx, k)
		if err != nil || !ok || o.Ref.Namespace == "" {
			continue
		}
		cs := registry.CredSet{Namespace: o.Ref.Namespace, ServiceAccount: o.ServiceAccount, PullSecrets: o.PullSecrets}
		if cs.ServiceAccount == "" {
			cs.ServiceAccount = "default"
		}
		if seen[cs.Key()] {
			continue
		}
		seen[cs.Key()] = true
		out = append(out, cs)
		if len(out) == maxAltCreds {
			break
		}
	}
	return out
}

// store persists a successful result. The image is marked unmatched before it is marked catalogued,
// so a match that does not complete is run again.
func (a *Acquirer) store(ctx context.Context, prev model.Image, r Request, res *Result) (*Result, error) {
	if len(res.SyftJSON) > MaxSBOMBytes {
		return nil, &AcquireError{Kind: FailQuarantine, Reason: fmt.Sprintf(reasonSBOMTooLarge, len(res.SyftJSON), MaxSBOMBytes)}
	}
	// Decoding takes several times the document's size in memory: bound what is decoded at once so
	// two large images cannot take the controller past its memory limit together.
	n := max(int64(len(res.SyftJSON)), 1)
	if err := a.decode.Acquire(ctx, n); err != nil {
		return nil, &AcquireError{Kind: FailTransient, Err: err}
	}
	defer a.decode.Release(n)
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
		return nil, storeErr("storing the SBOM", err)
	}
	if err := a.o.Store.MarkUnmatched(ctx, r.Digest, a.o.Now()); err != nil {
		return nil, storeErr("recording the image for matching", err)
	}
	img := a.base(prev, r)
	img.Status, img.StatusReason = model.ImageCatalogued, ""
	img.Source, img.ConfigUser, img.Coverage = out.Source, out.ConfigUser, cov
	if out.VersionAnnotation != "" {
		img.VersionAnnotation = out.VersionAnnotation
	}
	img.CataloguedAt, img.Attempts, img.QuarantinedUntil = a.o.Now(), 0, time.Time{}
	if err := a.o.Store.UpsertImage(ctx, img); err != nil {
		return nil, storeErr("storing the image", err)
	}
	a.catalogued.Add(1)
	return &out, nil
}

// storeErr makes a store failure transient: it says nothing about the image.
func storeErr(what string, err error) error {
	return &AcquireError{Kind: FailTransient, Reason: what, Err: err}
}

// match runs OnCatalogued for a digest marked unmatched and clears the mark once it succeeds. After
// matchAttemptLimit runs that did not, the image is quarantined: shown catalogFailed rather than
// catalogued with no findings, and catalogued and matched again when the quarantine ends.
func (a *Acquirer) match(ctx context.Context, digest string) {
	st := a.o.Store
	if a.o.OnCatalogued == nil {
		a.bookkeep(ctx, "clearing the match record", digest, st.MarkMatched)
		return
	}
	runs, err := st.BeginMatch(ctx, digest)
	if err != nil {
		a.o.Log.Error(err, "recording a match run", "digest", digest)
		return
	}
	if runs > matchAttemptLimit {
		if img, ok, err := st.GetImage(ctx, digest); err == nil && ok {
			a.quarantine(ctx, img, reasonMatchFailed)
		}
		a.bookkeep(ctx, "clearing the match record", digest, st.MarkMatched)
		return
	}
	mctx, cancel := context.WithTimeout(ctx, a.o.MatchTimeout)
	defer cancel()
	for i := 0; i < onCataloguedTries; i++ {
		if err = a.o.OnCatalogued(mctx, digest); err == nil {
			a.bookkeep(ctx, "clearing the match record", digest, st.MarkMatched)
			return
		}
		if i < onCataloguedTries-1 {
			select {
			case <-mctx.Done():
				i = onCataloguedTries
			case <-time.After(onCataloguedDelay):
			}
		}
	}
	a.o.Log.Error(err, "image catalogued hook failed; it runs again later", "digest", digest, "run", runs)
}

// rematch matches again every catalogued image whose match did not complete: the controller
// stopped during it, or it failed.
func (a *Acquirer) rematch(ctx context.Context) {
	unmatched, err := a.o.Store.UnmatchedImages(ctx)
	if err != nil {
		if ctx.Err() == nil {
			a.o.Log.Error(err, "listing images whose match did not complete")
		}
		return
	}
	for _, u := range unmatched {
		if ctx.Err() != nil {
			return
		}
		a.mu.Lock()
		_, busy := a.jobs[u.Digest]
		a.mu.Unlock()
		if !busy {
			a.match(ctx, u.Digest)
		}
	}
}

// bookkeep runs a store write that must happen even when ctx was cancelled by shutdown.
func (a *Acquirer) bookkeep(ctx context.Context, what, digest string, write func(context.Context, string) error) {
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), bookkeepingTimeout)
	defer cancel()
	if err := write(wctx, digest); err != nil {
		a.o.Log.Error(err, what, "digest", digest)
	}
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

// quarantine marks img catalogFailed with reason for QuarantineFor.
func (a *Acquirer) quarantine(ctx context.Context, img model.Image, reason string) {
	img.Status, img.StatusReason = model.ImageCatalogFailed, reason
	img.QuarantinedUntil = a.o.Now().Add(a.o.QuarantineFor)
	a.quarantined.Add(1)
	a.failed.Add(1)
	metrics.CatalogFailures.Inc()
	a.upsert(ctx, img)
	a.o.Log.Info("sbom acquisition quarantined", "digest", img.Digest, "reason", reason)
}

func (a *Acquirer) upsert(ctx context.Context, img model.Image) {
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), bookkeepingTimeout)
	defer cancel()
	if err := a.o.Store.UpsertImage(wctx, img); err != nil {
		a.o.Log.Error(err, "recording acquisition state", "digest", img.Digest)
	}
}

// fail records a failed attempt and returns how long to wait before retrying the digest (0: no retry).
func (a *Acquirer) fail(ctx context.Context, j *job, prev model.Image, r Request, err error) time.Duration {
	kind := KindOf(err)
	if ctx.Err() != nil {
		kind = FailTransient
	}
	reason := err.Error()
	var ae *AcquireError
	if errors.As(err, &ae) && ae.Reason != "" {
		reason = ae.Reason
	}
	if kind == FailCounted && cataloguerStopped(err) && a.overlapped(j) {
		// The cataloguer went down with more than one job in flight, so any of them may have taken it
		// down (an out-of-memory kill ends the whole catalog container). Run this image again on its
		// own before counting anything against it.
		a.mu.Lock()
		a.solo[r.Digest] = true
		a.mu.Unlock()
		a.o.Log.Info("sbom acquisition interrupted with other jobs in flight; retrying it alone", "digest", r.Digest)
		return a.o.RetryAfter
	}
	if kind == FailTransient {
		a.o.Log.Info("sbom acquisition failed; retrying", "digest", r.Digest, "kind", fmt.Sprint(kind), "reason", reason)
		return a.transientDelay(ctx, r.Digest)
	}
	a.resetTransient(r.Digest)
	now := a.o.Now()
	img := a.base(prev, r)
	if img.Status == "" {
		img.Status = model.ImagePending
	}
	var retry time.Duration
	switch kind {
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
			retry = a.o.RetryAfter
		}
	}
	a.failed.Add(1)
	metrics.CatalogFailures.Inc()
	a.upsert(ctx, img)
	a.o.Log.Info("sbom acquisition failed", "digest", r.Digest, "kind", fmt.Sprint(kind), "reason", reason)
	return retry
}

func (a *Acquirer) overlapped(j *job) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return j.overlapped
}

// transientDelay counts a transient failure of digest and returns the backoff before its retry:
// RetryAfter, doubling with each consecutive transient failure, at most maxTransientDelay. It is 0
// while shutting down.
func (a *Acquirer) transientDelay(ctx context.Context, digest string) time.Duration {
	if ctx.Err() != nil {
		return 0
	}
	a.mu.Lock()
	n := a.transient[digest]
	a.transient[digest] = n + 1
	a.mu.Unlock()
	d := a.o.RetryAfter
	for i := 0; i < n && d < maxTransientDelay; i++ {
		d *= 2
	}
	return min(d, maxTransientDelay)
}

func (a *Acquirer) resetTransient(digest string) {
	a.mu.Lock()
	delete(a.transient, digest)
	a.mu.Unlock()
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
