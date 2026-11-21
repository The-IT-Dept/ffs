package upgrade

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/eol"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/registry"
	"github.com/the-it-dept/ffs/internal/sbom"
	"github.com/the-it-dept/ffs/internal/store"
)

// Registry is the part of the registry client the resolver uses (*registry.Client).
type Registry interface {
	ListTags(ctx context.Context, repo string, cs registry.CredSet) ([]string, error)
	ResolveTag(ctx context.Context, repo, tag string, cs registry.CredSet) (string, error)
	PlatformManifest(ctx context.Context, repo, digest, platform string, cs registry.CredSet) (registry.Manifest, error)
}

// Acquirer catalogues a candidate platform manifest and stores its SBOM (*sbom.Acquirer).
type Acquirer interface {
	AcquireNow(ctx context.Context, r sbom.Request) (*sbom.Result, error)
}

// Scorer matches a catalogued candidate and scores its matches for an owner, storing nothing
// (*engine.Engine).
type Scorer interface {
	MatchCandidate(ctx context.Context, digest string) ([]model.Match, error)
	ScoreMatches(ctx context.Context, owner model.Owner, repo string, ms []model.Match) ([]model.Finding, error)
}

// Options configures a Resolver.
type Options struct {
	Store    *store.Store
	Registry Registry
	Acquirer Acquirer
	Scorer   Scorer
	EOL      *eol.Evaluator // nil = suggestions carry no end-of-life text
	Parser   *Parser
	Config   config.Config
	HTTP     *http.Client     // outbound HTTP beyond the registry, with the ffs User-Agent
	Now      func() time.Time // nil = time.Now
	Log      logr.Logger
}

const (
	transitionsCursor = "upgrade"       // last transition ID ConsumeTransitions read
	dailyCursor       = "upgrade-daily" // unix seconds of the last finished daily pass
	transitionsBatch  = 500
	consumeInterval   = 30 * time.Second
	dailyPeriod       = 24 * time.Hour
	defaultCandidates = 4
)

const (
	noteNoPath        = "no upgrade path in this repository"
	noteUnknown       = "current version unknown"
	noteStillAffected = "upgrade applied, still affected: "
)

// Resolver keeps an upgrade suggestion for every image repository on which a workload has an open,
// fixable finding at or above medium (spec §6.7). It scores candidate tags against the owner's
// findings, stores the result, and announces a new recommendation with UpgradeAvailable
// transitions, which never change state or priority. Owners are queued by new qualifying findings,
// by findings that stop qualifying while a suggestion is stored, by match changes on a stored
// candidate, by a rollout onto one and, at startup, when a restart may have left their suggestion
// out of date; all are resolved daily.
type Resolver struct {
	o Options

	resolveMu sync.Mutex // serialises ResolveOwner

	qmu    sync.Mutex
	queue  []string // owner keys, oldest first
	queued map[string]bool
	wake   chan struct{}
	// from holds, for each owner a transition queued and that is not resolved yet (queued, or being
	// resolved), the first transition that queued it. The stored transitions cursor stays below the
	// oldest of them (saveCursor), so a restart reads those transitions again and queues their owners.
	from map[string]int64
	read int64 // the last transition ConsumeTransitions read; valid once readSet
	// readSet is set once read and saved hold the stored cursor, read at the first ConsumeTransitions.
	readSet bool

	cmu   sync.Mutex // serialises saveCursor
	saved int64      // the transitions cursor last stored
}

// NewResolver returns a resolver with an empty queue.
func NewResolver(o Options) *Resolver {
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Resolver{o: o, queued: map[string]bool{}, from: map[string]int64{}, wake: make(chan struct{}, 1)}
}

func (r *Resolver) now() time.Time { return r.o.Now().UTC() }

// clusterLevel reports whether kind is a cluster-level subject, whose advice is not an image upgrade.
func clusterLevel(o model.OwnerRef) bool { return o.ClusterLevel() }

// Run is the leader-only worker (a manager.Runnable). It starts as startup describes, then, until
// ctx is done, consumes the transitions outbox every 30 seconds, runs the daily pass at
// Upgrades.DailyAt (UTC) and resolves queued owners one at a time. Errors are logged, never
// returned, except an invalid DailyAt.
func (r *Resolver) Run(ctx context.Context) error {
	// Upgrade work is never more urgent than inventory resolution: it leaves a registry's last 20%
	// of budget to the inventory (and candidate pulls run low-priority in the acquirer anyway).
	ctx = registry.LowPriority(ctx)
	at := r.o.Config.Upgrades.DailyAt
	if _, err := nextDaily(r.now(), at); err != nil {
		return fmt.Errorf("upgrade: dailyAt %q: %w", at, err)
	}
	r.startup(ctx)

	tick := time.NewTicker(consumeInterval)
	defer tick.Stop()
	next, _ := nextDaily(r.now(), at)
	daily := time.NewTimer(next.Sub(r.now()))
	defer daily.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			r.consume(ctx)
		case <-daily.C:
			r.dailyPass(ctx)
			next, _ = nextDaily(r.now(), at)
			daily.Reset(next.Sub(r.now()))
		case <-r.wake:
			r.resolveNext(ctx)
		}
	}
}

// startup drains the transitions outbox, queues the owners whose suggestions a restart may have left
// out of date (store.OwnersToResolve: the queue is held in memory only), then runs the daily pass
// when the last one finished more than a day ago. The outbox is read from the stored cursor, which
// stays below every transition whose owner was still queued or being resolved (saveCursor), so the
// owners transitions queued before the restart are queued again; OwnersToResolve adds those that
// stale suggestions and rollouts queued. Consuming first lets the daily pass dequeue the owners it
// resolves, so none is resolved twice.
func (r *Resolver) startup(ctx context.Context) {
	r.consume(ctx)
	if keys, err := r.o.Store.OwnersToResolve(ctx); err != nil {
		r.o.Log.Error(err, "finding the owners to resolve after a restart failed")
	} else {
		r.enqueue(keys...)
	}
	if last, err := r.o.Store.Cursor(ctx, dailyCursor); err != nil {
		r.o.Log.Error(err, "reading the time of the last daily upgrade pass failed")
	} else if r.now().Sub(time.Unix(last, 0)) > dailyPeriod {
		r.dailyPass(ctx)
	}
}

// nextDaily returns the first time after now at the "15:04" UTC time of day at.
func nextDaily(now time.Time, at string) (time.Time, error) {
	hm, err := time.Parse("15:04", at)
	if err != nil {
		return time.Time{}, err
	}
	now = now.UTC()
	t := time.Date(now.Year(), now.Month(), now.Day(), hm.Hour(), hm.Minute(), 0, 0, time.UTC)
	if !t.After(now) {
		t = t.AddDate(0, 0, 1)
	}
	return t, nil
}

// consume reads the transitions outbox until it is drained.
func (r *Resolver) consume(ctx context.Context) {
	for ctx.Err() == nil {
		n, err := r.ConsumeTransitions(ctx)
		if err != nil {
			if ctx.Err() == nil {
				r.o.Log.Error(err, "reading transitions for upgrade suggestions failed")
			}
			return
		}
		if n < transitionsBatch {
			return
		}
	}
}

// dailyPass runs DailyPass and logs its failure.
func (r *Resolver) dailyPass(ctx context.Context) {
	if err := r.DailyPass(ctx); err != nil && ctx.Err() == nil {
		r.o.Log.Error(err, "daily upgrade pass failed")
	}
}

// resolveNext resolves the oldest queued owner, and wakes the worker again when more are queued. An
// owner whose resolution shutdown interrupts is not released (release), so the next start queues it
// again.
func (r *Resolver) resolveNext(ctx context.Context) {
	key, ok, more := r.pop()
	if !ok {
		return
	}
	err := r.ResolveOwner(ctx, key)
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		r.o.Log.Error(err, "resolving upgrades failed", "owner", key)
	}
	r.release(ctx, key)
	if more {
		r.signal()
	}
}

// DailyPass resolves every owner, then records the pass time. An owner that fails is
// logged and the pass goes on; the count of failures is returned.
func (r *Resolver) DailyPass(ctx context.Context) error {
	owners, err := r.o.Store.ListOwners(ctx)
	if err != nil {
		return fmt.Errorf("upgrade: list owners: %w", err)
	}
	failed := 0
	for _, o := range owners {
		if err := ctx.Err(); err != nil {
			return err
		}
		key := o.Ref.Key()
		r.dequeue(key)
		if err := r.ResolveOwner(ctx, key); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			failed++
			r.o.Log.Error(err, "resolving upgrades failed", "owner", key)
		}
		r.release(ctx, key)
	}
	if err := r.o.Store.SetCursor(ctx, dailyCursor, r.now().Unix()); err != nil {
		return fmt.Errorf("upgrade: record daily pass: %w", err)
	}
	if failed > 0 {
		return fmt.Errorf("upgrade: %d of %d owners failed", failed, len(owners))
	}
	return nil
}

// ConsumeTransitions reads up to 500 transitions after the "upgrade" cursor and queues the owners
// of findings that newly qualify for a suggestion: open at medium or above, with a fix, and just
// created, reopened, raised in priority or given a fix. It also queues every owner with a stored
// suggestion that has a finding leave a qualifying state (resolved, excepted or lowered below
// medium), so a suggestion does not outlive its reason. UpgradeAvailable transitions, the
// resolver's own, are ignored. It reads on from the last transition it read, stores the cursor
// (saveCursor) and returns the number of transitions read.
func (r *Resolver) ConsumeTransitions(ctx context.Context) (int, error) {
	after, err := r.readFrom(ctx)
	if err != nil {
		return 0, err
	}
	ts, err := r.o.Store.TransitionsAfter(ctx, after, transitionsBatch)
	if err != nil {
		return 0, fmt.Errorf("upgrade: transitions: %w", err)
	}
	if len(ts) == 0 {
		return 0, nil
	}
	var wanted, leaving []model.Transition
	var fps, leavingKeys []string
	for _, t := range ts {
		switch {
		case qualifies(t) && !clusterLevel(t.Owner):
			wanted = append(wanted, t)
			fps = append(fps, t.Fingerprint)
		case leaves(t):
			leaving = append(leaving, t)
			leavingKeys = append(leavingKeys, t.Owner.Key())
		}
	}
	var queue []model.Transition // the transitions that queue their owner
	if len(fps) > 0 {
		fs, err := r.o.Store.FindingsByFingerprint(ctx, fps)
		if err != nil {
			return 0, fmt.Errorf("upgrade: findings of transitions: %w", err)
		}
		for _, t := range wanted {
			if f, ok := fs[t.Fingerprint]; ok && f.FixAvailable {
				queue = append(queue, t)
			}
		}
	}
	if len(leaving) > 0 {
		has, err := r.o.Store.OwnersWithSuggestions(ctx, leavingKeys)
		if err != nil {
			return 0, fmt.Errorf("upgrade: suggestions of transitions: %w", err)
		}
		for _, t := range leaving {
			if has[t.Owner.Key()] {
				queue = append(queue, t)
			}
		}
	}
	r.enqueueTransitions(queue)
	r.qmu.Lock()
	r.read = ts[len(ts)-1].ID
	r.qmu.Unlock()
	if err := r.saveCursor(ctx); err != nil {
		return 0, err
	}
	return len(ts), nil
}

// readFrom is the transition ConsumeTransitions reads after: the last one it read, or the stored
// cursor the first time.
func (r *Resolver) readFrom(ctx context.Context) (int64, error) {
	r.qmu.Lock()
	read, ok := r.read, r.readSet
	r.qmu.Unlock()
	if ok {
		return read, nil
	}
	cur, err := r.o.Store.Cursor(ctx, transitionsCursor)
	if err != nil {
		return 0, fmt.Errorf("upgrade: transitions cursor: %w", err)
	}
	r.cmu.Lock()
	r.saved = cur
	r.cmu.Unlock()
	r.qmu.Lock()
	r.read, r.readSet = cur, true
	r.qmu.Unlock()
	return cur, nil
}

// saveCursor stores the transitions cursor: just below the oldest transition whose owner is queued
// or being resolved (from), else the last transition read. It writes only when that moved, and
// nothing before the first ConsumeTransitions.
func (r *Resolver) saveCursor(ctx context.Context) error {
	r.cmu.Lock()
	defer r.cmu.Unlock()
	r.qmu.Lock()
	if !r.readSet {
		r.qmu.Unlock()
		return nil
	}
	to := r.read
	for _, id := range r.from {
		to = min(to, id-1)
	}
	r.qmu.Unlock()
	if to == r.saved {
		return nil
	}
	if err := r.o.Store.SetCursor(ctx, transitionsCursor, to); err != nil {
		return fmt.Errorf("upgrade: set transitions cursor: %w", err)
	}
	r.saved = to
	return nil
}

// release records that key was resolved: its transitions no longer hold the cursor back.
func (r *Resolver) release(ctx context.Context, key string) {
	r.qmu.Lock()
	_, held := r.from[key]
	delete(r.from, key)
	r.qmu.Unlock()
	if !held {
		return
	}
	if err := r.saveCursor(ctx); err != nil && ctx.Err() == nil {
		r.o.Log.Error(err, "recording the upgrade transitions read failed")
	}
}

// qualifies reports whether t may make its owner newly qualify for a suggestion.
func qualifies(t model.Transition) bool {
	if t.Trigger == model.TriggerUpgradeAvailable || t.ToState != model.StateOpen || t.ToPriority < model.PriorityMedium {
		return false
	}
	created, reopened := t.FromState == "", t.FromState != model.StateOpen
	return created || reopened || t.ToPriority > t.FromPriority || t.Trigger == model.TriggerFixAvailable
}

// leaves reports whether t takes a finding out of a qualifying state: from open at medium or above
// to any other state, or below medium.
func leaves(t model.Transition) bool {
	return t.Trigger != model.TriggerUpgradeAvailable && t.FromState == model.StateOpen && t.FromPriority >= model.PriorityMedium &&
		(t.ToState != model.StateOpen || t.ToPriority < model.PriorityMedium)
}

// MatchesReplaced is the engine.Observer hook: a stored candidate's matches changed, so the
// suggestions that scored it are marked stale and their owners queued to be resolved again. A
// stale suggestion stands until then, and survives a restart, which queues its owner again.
func (r *Resolver) MatchesReplaced(ctx context.Context, digests []string) {
	keys, err := r.o.Store.SuggestionKeysForDigests(ctx, digests)
	if err != nil {
		r.o.Log.Error(err, "finding the suggestions of re-matched digests failed")
		return
	}
	if err := r.o.Store.MarkSuggestionsStale(ctx, keys); err != nil {
		r.o.Log.Error(err, "marking re-matched suggestions stale failed")
	}
	owners := map[string]bool{}
	for _, k := range keys {
		owners[k.OwnerKey] = true
	}
	r.enqueue(slices.Sorted(maps.Keys(owners))...)
}

// OwnersRecomputed is the engine.Observer hook: an owner now running one of its stored candidates
// (a suggested upgrade was rolled out) is queued, so its suggestion says whether that helped.
func (r *Resolver) OwnersRecomputed(ctx context.Context, keys []string) {
	for _, key := range keys {
		if model.ClusterLevelKey(key) {
			continue
		}
		o, ok, err := r.o.Store.GetOwner(ctx, key)
		if err != nil {
			r.o.Log.Error(err, "reading a recomputed owner failed", "owner", key)
			continue
		}
		if !ok {
			continue
		}
		var digests []string
		for _, c := range o.Containers {
			if c.Digest != "" {
				digests = append(digests, c.Digest)
			}
		}
		if len(digests) == 0 {
			continue
		}
		sks, err := r.o.Store.SuggestionKeysForDigests(ctx, digests)
		if err != nil {
			r.o.Log.Error(err, "finding the suggestions of a recomputed owner failed", "owner", key)
			continue
		}
		if slices.ContainsFunc(sks, func(k store.SuggestionKey) bool { return k.OwnerKey == key }) {
			r.enqueue(key)
		}
	}
}

// Pending returns the queued owner keys, oldest first.
func (r *Resolver) Pending() []string {
	r.qmu.Lock()
	defer r.qmu.Unlock()
	return slices.Clone(r.queue)
}

// enqueue queues the keys not already queued and wakes the worker.
func (r *Resolver) enqueue(keys ...string) {
	r.qmu.Lock()
	added := r.add(keys)
	r.qmu.Unlock()
	if added {
		r.signal()
	}
}

// enqueueTransitions queues the owners of ts, oldest transition first, and records for each owner
// the first transition that queued it (from).
func (r *Resolver) enqueueTransitions(ts []model.Transition) {
	slices.SortStableFunc(ts, func(a, b model.Transition) int { return cmp.Compare(a.ID, b.ID) })
	keys := make([]string, 0, len(ts))
	r.qmu.Lock()
	for _, t := range ts {
		k := t.Owner.Key()
		if _, ok := r.from[k]; !ok {
			r.from[k] = t.ID
		}
		keys = append(keys, k)
	}
	added := r.add(keys)
	r.qmu.Unlock()
	if added {
		r.signal()
	}
}

// add queues the keys not already queued, under qmu, and reports whether any was.
func (r *Resolver) add(keys []string) bool {
	added := false
	for _, k := range keys {
		if !r.queued[k] {
			r.queued[k] = true
			r.queue = append(r.queue, k)
			added = true
		}
	}
	return added
}

func (r *Resolver) signal() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// pop removes the oldest queued key; more reports whether others remain. The key stays in from until
// it is released.
func (r *Resolver) pop() (key string, ok, more bool) {
	r.qmu.Lock()
	defer r.qmu.Unlock()
	if len(r.queue) == 0 {
		return "", false, false
	}
	key, r.queue = r.queue[0], r.queue[1:]
	delete(r.queued, key)
	return key, true, len(r.queue) > 0
}

// dequeue removes key from the queue, if queued. The key stays in from until it is released.
func (r *Resolver) dequeue(key string) {
	r.qmu.Lock()
	defer r.qmu.Unlock()
	if !r.queued[key] {
		return
	}
	delete(r.queued, key)
	r.queue = slices.DeleteFunc(r.queue, func(k string) bool { return k == key })
}

// ResolveOwner recomputes the owner's suggestion on every image repository where it has an open,
// fixable finding at or above medium, and deletes its suggestions on every other repository.
// Cluster and container-runtime owners get patch-release advice instead (AdviseCluster,
// AdviseRuntime); unknown owners are skipped.
func (r *Resolver) ResolveOwner(ctx context.Context, key string) error {
	r.resolveMu.Lock()
	defer r.resolveMu.Unlock()
	o, ok, err := r.o.Store.GetOwner(ctx, key)
	if err != nil {
		return fmt.Errorf("upgrade: owner %s: %w", key, err)
	}
	if !ok {
		return nil
	}
	fs, err := r.o.Store.FindingsForOwner(ctx, key)
	if err != nil {
		return fmt.Errorf("upgrade: findings of %s: %w", key, err)
	}
	if clusterLevel(o.Ref) {
		return r.resolveClusterLevel(ctx, o, fs)
	}

	running := map[string]bool{}
	for _, c := range o.Containers {
		if c.Repo != "" {
			running[c.Repo] = true
		}
	}
	known := maps.Clone(running) // every repository that may hold a suggestion
	open := map[string][]model.Finding{}
	qualifying := map[string]bool{}
	for _, f := range fs {
		known[f.ImageRepo] = true
		if f.State != model.StateOpen {
			continue
		}
		open[f.ImageRepo] = append(open[f.ImageRepo], f)
		if f.Priority >= model.PriorityMedium && f.FixAvailable && running[f.ImageRepo] {
			qualifying[f.ImageRepo] = true
		}
	}

	var errs []error
	for _, repo := range slices.Sorted(maps.Keys(qualifying)) {
		if err := r.resolveRepo(ctx, o, repo, open[repo]); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			errs = append(errs, err)
		}
	}
	var stale []string
	for repo := range known {
		if !qualifying[repo] {
			stale = append(stale, repo)
		}
	}
	if len(stale) > 0 {
		slices.Sort(stale)
		if err := r.o.Store.DeleteSuggestions(ctx, key, stale); err != nil {
			errs = append(errs, fmt.Errorf("upgrade: delete suggestions of %s: %w", key, err))
		}
		// a repository that qualifies again later has its recommendation announced afresh
		if err := r.o.Store.DeleteAnnouncements(ctx, key, stale); err != nil {
			errs = append(errs, fmt.Errorf("upgrade: delete announcements of %s: %w", key, err))
		}
	}
	return errors.Join(errs...)
}

// repoState is what an owner runs on one image repository.
type repoState struct {
	tag       string           // current tag: "" for a digest-only reference
	version   TagVersion       // parsed from the tag, else from the image's version annotation
	known     bool             // version is set
	digests   []string         // platform manifests the owner runs
	runs      map[string]bool  // digests and their index digests
	creds     registry.CredSet // the owner's pull credentials
	platforms []string         // "linux/<arch>" of every architecture the owner runs on
}

// current returns what o runs on repo.
func (r *Resolver) current(ctx context.Context, o model.Owner, repo string) (repoState, error) {
	cur := repoState{
		runs:  map[string]bool{},
		creds: registry.CredSet{Namespace: o.Ref.Namespace, ServiceAccount: o.ServiceAccount, PullSecrets: o.PullSecrets},
	}
	var annotation string
	var used []string // platforms of the containers, when the owner's architectures are unknown
	first := true
	for _, c := range o.Containers {
		if c.Repo != repo {
			continue
		}
		if first {
			cur.tag, first = currentTag(c.ImageRef), false
		}
		if c.Platform != "" && !slices.Contains(used, c.Platform) {
			used = append(used, c.Platform)
		}
		if c.Digest == "" || slices.Contains(cur.digests, c.Digest) {
			continue
		}
		cur.digests = append(cur.digests, c.Digest)
		cur.runs[c.Digest] = true
		img, ok, err := r.o.Store.GetImage(ctx, c.Digest)
		if err != nil {
			return repoState{}, fmt.Errorf("upgrade: image %s: %w", c.Digest, err)
		}
		if ok {
			if img.IndexDigest != "" {
				cur.runs[img.IndexDigest] = true
			}
			if annotation == "" {
				annotation = img.VersionAnnotation
			}
		}
	}
	for _, a := range o.Arch {
		if p := "linux/" + a; !slices.Contains(cur.platforms, p) {
			cur.platforms = append(cur.platforms, p)
		}
	}
	if len(cur.platforms) == 0 {
		cur.platforms = used
	}
	if cur.tag != "" {
		cur.version, cur.known = r.o.Parser.Parse(repo, cur.tag)
	}
	if !cur.known && annotation != "" {
		cur.version, cur.known = FloatingVersion(cur.tag, annotation)
	}
	return cur, nil
}

// currentTag returns the tag of an image reference, with any "@digest" dropped: "latest" when
// there is none, and "" for a digest-only reference.
func currentTag(ref string) string {
	name, _, pinned := strings.Cut(ref, "@")
	if i := strings.LastIndex(name, ":"); i > strings.LastIndex(name, "/") {
		return name[i+1:]
	}
	if pinned {
		return ""
	}
	return "latest"
}

// candidate is a tag to score and the digest it resolved to.
type candidate struct {
	tag    string
	tier   model.Tier
	digest string
}

// resolveRepo recomputes, stores and announces the owner's suggestion on repo. before holds the
// owner's open findings on repo. A candidate that fails at any step is dropped for this pass. When
// something failed and no candidate survived, a stored suggestion stands until the next pass, so a
// registry outage does not wipe it; with none stored, the tier-none result is stored.
func (r *Resolver) resolveRepo(ctx context.Context, o model.Owner, repo string, before []model.Finding) error {
	key := o.Ref.Key()
	log := r.o.Log.WithValues("owner", key, "repo", repo)
	cur, err := r.current(ctx, o, repo)
	if err != nil {
		return err
	}
	prev, hadPrev, err := r.o.Store.GetSuggestion(ctx, key, repo)
	if err != nil {
		return fmt.Errorf("upgrade: suggestion of %s on %s: %w", key, repo, err)
	}
	var applied *store.AppliedUpgrade
	if hadPrev {
		applied = appliedUpgrade(prev, cur)
	}
	cands, incomplete := r.candidates(ctx, repo, cur, log)
	scored := r.score(ctx, o, repo, cur, before, cands, log)
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(scored) == 0 && (incomplete || len(cands) > 0) && hadPrev {
		log.Info("no upgrade candidate survived this pass; the stored suggestion stands")
		return nil
	}

	now := r.now()
	rec, alts := Recommend(scored)
	sg := model.Suggestion{Repo: repo, FromTag: cur.tag, Tier: model.TierNone, ComputedAt: now}
	if rec != nil {
		sg = suggestionOf(repo, cur.tag, *rec, now)
	}
	for _, a := range alts {
		sg.Alternatives = append(sg.Alternatives, suggestionOf(repo, cur.tag, a, now))
	}
	if sg.EOL, err = r.eolText(ctx, repo, cur, now); err != nil {
		return err
	}
	// tags are listed only for a known version: without one, nothing says there is no path
	if len(cands) == 0 && !incomplete && cur.known {
		sg.Notes = append(sg.Notes, noteNoPath)
	}
	if !cur.known {
		sg.Notes = append(sg.Notes, noteUnknown)
	}
	if applied != nil {
		if ids := stillOpen(applied.FixedIDs, before); len(ids) > 0 {
			sg.Notes = append(sg.Notes, noteStillAffected+strings.Join(ids, ", "))
		} else {
			applied = nil // everything it was to fix is fixed: nothing left to say
		}
	}

	if err := r.o.Store.PutSuggestionApplied(ctx, key, sg, candidateRows(scored), applied); err != nil {
		return fmt.Errorf("upgrade: store suggestion of %s on %s: %w", key, repo, err)
	}
	if sg.Tier == model.TierNone {
		return nil
	}
	// compared with the last announced target, not the previous suggestion, which a pass that
	// recommended nothing may have replaced: resolving to the same target again must not announce it twice
	toTag, toDigest, announced, err := r.o.Store.Announced(ctx, key, repo)
	if err != nil {
		return fmt.Errorf("upgrade: announcement of %s on %s: %w", key, repo, err)
	}
	if announced && toTag == sg.ToTag && toDigest == sg.ToDigest {
		return nil
	}
	return r.announce(ctx, key, sg, before, now)
}

// candidates returns repo's upgrade candidates nearest first, at most MaxCandidatesPerRepo: a
// refresh when the current tag now points at an image the owner does not run, then the best patch,
// minor and major tags. A tag that fails to resolve is skipped, and when the tags cannot be listed
// only the refresh is returned; either failure is logged and makes incomplete true.
func (r *Resolver) candidates(ctx context.Context, repo string, cur repoState, log logr.Logger) (out []candidate, incomplete bool) {
	limit := r.o.Config.Upgrades.MaxCandidatesPerRepo
	if limit <= 0 {
		limit = defaultCandidates
	}
	if cur.tag != "" {
		d, err := r.o.Registry.ResolveTag(ctx, repo, cur.tag, cur.creds)
		switch {
		case err != nil:
			incomplete = true
			log.Info("skipping upgrade candidate this pass", "tag", cur.tag, "tier", model.TierRefresh, "error", err.Error())
		case !cur.runs[d]:
			out = append(out, candidate{cur.tag, model.TierRefresh, d})
		}
	}
	if !cur.known || len(out) >= limit {
		return out, incomplete
	}
	tags, err := r.o.Registry.ListTags(ctx, repo, cur.creds)
	if err != nil {
		log.Info("listing tags failed; skipping the patch, minor and major candidates this pass", "error", err.Error())
		return out, true
	}
	best := r.o.Parser.Best(repo, cur.version, tags)
	for _, tier := range []model.Tier{model.TierPatch, model.TierMinor, model.TierMajor} {
		v, ok := best[tier]
		if !ok {
			continue
		}
		if len(out) >= limit {
			break
		}
		d, err := r.o.Registry.ResolveTag(ctx, repo, v.Tag, cur.creds)
		if err != nil {
			incomplete = true
			log.Info("skipping upgrade candidate this pass", "tag", v.Tag, "tier", tier, "error", err.Error())
			continue
		}
		if !cur.runs[d] {
			out = append(out, candidate{v.Tag, tier, d})
		}
	}
	return out, incomplete
}

// score scores each candidate. A candidate that fails at any step is logged and dropped for this
// pass.
func (r *Resolver) score(ctx context.Context, o model.Owner, repo string, cur repoState, before []model.Finding,
	cands []candidate, log logr.Logger) []Scored {
	var out []Scored
	for _, c := range cands {
		if ctx.Err() != nil {
			return nil
		}
		s, err := r.scoreCandidate(ctx, o, repo, cur, before, c)
		if err != nil {
			log.Info("skipping upgrade candidate this pass", "tag", c.tag, "tier", c.tier, "error", err.Error())
			continue
		}
		out = append(out, s)
	}
	return out
}

// scoreCandidate catalogues and matches c's manifest for every platform the owner runs on, then
// scores all their matches together against before.
func (r *Resolver) scoreCandidate(ctx context.Context, o model.Owner, repo string, cur repoState, before []model.Finding,
	c candidate) (Scored, error) {
	if len(cur.platforms) == 0 {
		return Scored{}, errors.New("the owner's platforms are unknown")
	}
	platforms := make(map[string]string, len(cur.platforms))
	var ms []model.Match
	for _, p := range cur.platforms {
		m, err := r.o.Registry.PlatformManifest(ctx, repo, c.digest, p, cur.creds)
		if err != nil {
			return Scored{}, fmt.Errorf("resolving the %s manifest: %w", p, err)
		}
		req := sbom.Request{Repo: repo, Digest: m.Digest, IndexDigest: m.IndexDigest, Platform: p, Creds: cur.creds}
		if _, err := r.o.Acquirer.AcquireNow(ctx, req); err != nil {
			return Scored{}, fmt.Errorf("cataloguing %s: %w", m.Digest, err)
		}
		got, err := r.o.Scorer.MatchCandidate(ctx, m.Digest)
		if err != nil {
			return Scored{}, fmt.Errorf("matching %s: %w", m.Digest, err)
		}
		ms = append(ms, got...)
		platforms[p] = m.Digest
	}
	after, err := r.o.Scorer.ScoreMatches(ctx, o, repo, ms)
	if err != nil {
		return Scored{}, fmt.Errorf("scoring: %w", err)
	}
	fixes, remaining, introduces, fixedIDs, clears := Score(before, after)
	return Scored{Tag: c.tag, IndexDigest: c.digest, Tier: c.tier, Platforms: platforms, Fixes: fixes,
		Remaining: remaining, Introduces: introduces, FixedIDs: fixedIDs, ClearsUrgentHigh: clears}, nil
}

// suggestionOf is the suggestion to move from tag from to the scored candidate s.
func suggestionOf(repo, from string, s Scored, now time.Time) model.Suggestion {
	return model.Suggestion{Repo: repo, FromTag: from, ToTag: s.Tag, ToDigest: s.IndexDigest, Tier: s.Tier,
		Fixes: s.Fixes, Remaining: s.Remaining, Introduces: s.Introduces, FixedIDs: s.FixedIDs, ComputedAt: now}
}

// eolText is the support status of the distro and runtimes of the image the owner runs (eol.Support),
// "unknown" when none is known, and empty without an evaluator.
func (r *Resolver) eolText(ctx context.Context, repo string, cur repoState, now time.Time) (string, error) {
	if r.o.EOL == nil {
		return "", nil
	}
	if len(cur.digests) == 0 {
		return eol.Unknown, nil
	}
	pkgs, err := r.o.Store.PackagesForImage(ctx, cur.digests[0])
	if err != nil {
		return "", fmt.Errorf("upgrade: packages of %s: %w", cur.digests[0], err)
	}
	return eol.JoinSupport(r.o.EOL.ImageEOL(repo, pkgs), now), nil
}

// appliedUpgrade returns the upgrade the owner now runs, from its stored suggestion prev: the
// recommendation when the owner runs one of its manifests, else the upgrade applied earlier while
// the owner still runs it; otherwise nil.
func appliedUpgrade(prev store.OwnerSuggestion, cur repoState) *store.AppliedUpgrade {
	runs := func(ds []string) bool {
		return slices.ContainsFunc(ds, func(d string) bool { return slices.Contains(cur.digests, d) })
	}
	if sg := prev.Suggestion; sg.Tier != model.TierNone && sg.ToTag != "" {
		var ds []string
		for _, c := range prev.Candidates {
			if c.Tag == sg.ToTag && c.Tier == sg.Tier {
				ds = append(ds, c.Digest)
			}
		}
		if runs(ds) {
			return &store.AppliedUpgrade{Tag: sg.ToTag, Tier: sg.Tier, Digests: ds, FixedIDs: slices.Clone(sg.FixedIDs)}
		}
	}
	if a := prev.Applied; a != nil && runs(a.Digests) {
		return a
	}
	return nil
}

// stillOpen returns the sorted advisories of ids that have an open finding in before.
func stillOpen(ids []string, before []model.Finding) []string {
	var out []string
	for _, f := range before {
		if f.State == model.StateOpen && slices.Contains(ids, f.AdvisoryID) && !slices.Contains(out, f.AdvisoryID) {
			out = append(out, f.AdvisoryID)
		}
	}
	slices.Sort(out)
	return out
}

// candidateRows lists every scored candidate's platform manifests, in candidate then platform order.
func candidateRows(scored []Scored) []store.CandidateDigest {
	var out []store.CandidateDigest
	for _, s := range scored {
		for _, p := range slices.Sorted(maps.Keys(s.Platforms)) {
			out = append(out, store.CandidateDigest{Tag: s.Tag, Tier: s.Tier, Platform: p, Digest: s.Platforms[p]})
		}
	}
	return out
}

// announce appends an UpgradeAvailable transition for each open finding the suggestion fixes and
// records the suggestion's target as announced, in one transaction. State, priority and provisional
// are unchanged: an available upgrade never moves priority (spec §6.6).
func (r *Resolver) announce(ctx context.Context, key string, sg model.Suggestion, before []model.Finding, now time.Time) error {
	var ts []model.Transition
	for _, f := range before {
		if !slices.Contains(sg.FixedIDs, f.AdvisoryID) {
			continue
		}
		ts = append(ts, model.Transition{
			Fingerprint: f.Fingerprint, Owner: f.Owner, AdvisoryID: f.AdvisoryID,
			FromState: f.State, ToState: f.State, FromPriority: f.Priority, ToPriority: f.Priority,
			Trigger: model.TriggerUpgradeAvailable, Provisional: f.Provisional, At: now,
		})
	}
	if len(ts) == 0 {
		return nil
	}
	if err := r.o.Store.AnnounceSuggestion(ctx, key, sg, ts); err != nil {
		return fmt.Errorf("upgrade: announce %s to %s: %w", Target(sg), key, err)
	}
	return nil
}
