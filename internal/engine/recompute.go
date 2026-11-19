package engine

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/the-it-dept/ffs/internal/findings"
	"github.com/the-it-dept/ffs/internal/match"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

// Recompute rebuilds the findings of the owners keys and writes the changes, with trig as the
// trigger of their transitions. The findings of every key that recomputed are written in one
// ApplyFindings call even when another key failed; the failures are returned together.
func (e *Engine) Recompute(ctx context.Context, keys []string, trig model.Trigger) error {
	e.running.Add(1)
	defer e.running.Add(-1)
	_, err := e.recompute(ctx, keys, trig)
	return err
}

// pass is the state one Recompute call shares across its owners.
type pass struct {
	trig   model.Trigger
	now    time.Time
	builds []time.Time
	rules  []findings.ExceptionRule
	canon  map[string]string // advisory id → canonical, cached for the call
}

// recompute is Recompute, also returning the keys whose findings were not written. Observers hear
// about the keys whose findings were, once the recompute lock is released.
func (e *Engine) recompute(ctx context.Context, keys []string, trig model.Trigger) ([]string, error) {
	failed, err := e.recomputeLocked(ctx, keys, trig)
	var written []string
	for _, k := range keys {
		if !slices.Contains(failed, k) {
			written = append(written, k)
		}
	}
	e.ownersRecomputed(ctx, written)
	return failed, err
}

// recomputeLocked rebuilds and writes the findings of keys under the recompute lock and returns the
// keys whose findings were not written.
func (e *Engine) recomputeLocked(ctx context.Context, keys []string, trig model.Trigger) ([]string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	builds, err := e.o.Store.GrypeDBBuilds(ctx)
	if err != nil {
		return keys, fmt.Errorf("engine: grype DB builds: %w", err)
	}
	var rules []findings.ExceptionRule
	if e.o.Exceptions != nil {
		if rules, err = e.o.Exceptions.ExceptionRules(ctx); err != nil {
			return keys, fmt.Errorf("engine: exception rules: %w", err)
		}
	}
	p := &pass{trig: trig, now: e.now(), builds: builds, rules: rules, canon: map[string]string{}}

	var (
		ups    []model.Finding
		ts     []model.Transition
		done   []string
		failed []string
		errs   []error
		wrote  bool
	)
	for _, key := range keys {
		u, t, rekeyed, err := e.recomputeOwner(ctx, p, key)
		wrote = wrote || rekeyed
		if err != nil {
			failed = append(failed, key)
			errs = append(errs, fmt.Errorf("engine: recompute %s: %w", key, err))
			continue
		}
		done = append(done, key)
		ups, ts = append(ups, u...), append(ts, t...)
	}
	if len(ups) > 0 || len(ts) > 0 {
		if err := e.o.Store.ApplyFindings(ctx, ups, ts); err != nil {
			failed = append(failed, done...)
			errs = append(errs, fmt.Errorf("engine: apply findings: %w", err))
		} else {
			wrote = true
		}
	}
	if wrote {
		e.signal()
	}
	return failed, errors.Join(errs...)
}

// recomputeOwner returns the finding upserts and transitions of one owner. rekeyed reports whether
// alias re-keys were written for it.
func (e *Engine) recomputeOwner(ctx context.Context, p *pass, key string) (ups []model.Finding, ts []model.Transition, rekeyed bool, err error) {
	old, err := e.o.Store.FindingsForOwner(ctx, key)
	if err != nil {
		return nil, nil, false, fmt.Errorf("stored findings: %w", err)
	}
	old, rks, err := e.rekey(ctx, p, old)
	if err != nil {
		return nil, nil, false, err
	}
	if len(rks) > 0 {
		if err := e.o.Store.RekeyFindings(ctx, rks); err != nil {
			return nil, nil, false, fmt.Errorf("re-key findings: %w", err)
		}
		rekeyed = true
	}
	built, w, err := e.build(ctx, p, key, old)
	if err != nil {
		return nil, nil, rekeyed, err
	}
	ups, ts = findings.Diff(old, built, w, p.now, p.trig)
	return ups, ts, rekeyed, nil
}

// rekey is the alias re-key pre-pass. A stored finding whose advisory now resolves to another
// canonical id (a GHSA gained a CVE) moves to the canonical's fingerprint, so Diff sees it as the
// same finding and emits no transition. It returns the stored findings as they will be once rks
// are applied: a finding whose new fingerprint is already taken is dropped, as RekeyFindings
// deletes it.
func (e *Engine) rekey(ctx context.Context, p *pass, old []model.Finding) ([]model.Finding, []store.FindingRekey, error) {
	taken := make(map[string]bool, len(old))
	for _, f := range old {
		taken[f.Fingerprint] = true
	}
	out := make([]model.Finding, 0, len(old))
	var rks []store.FindingRekey
	for _, f := range old {
		c, err := p.canonical(ctx, e.o.Store, f.AdvisoryID)
		if err != nil {
			return nil, nil, err
		}
		if c == f.AdvisoryID {
			out = append(out, f)
			continue
		}
		fp := model.FindingFingerprint(e.o.Config.ClusterName, f.Owner, f.ImageRepo, c)
		rks = append(rks, store.FindingRekey{OldFingerprint: f.Fingerprint, NewFingerprint: fp, AdvisoryID: c})
		delete(taken, f.Fingerprint)
		if taken[fp] {
			continue
		}
		taken[fp] = true
		f.Fingerprint, f.AdvisoryID = fp, c
		out = append(out, f)
	}
	return out, rks, nil
}

func (p *pass) canonical(ctx context.Context, st Store, id string) (string, error) {
	if c, ok := p.canon[id]; ok {
		return c, nil
	}
	c, err := st.Canonical(ctx, id)
	if err != nil {
		return "", fmt.Errorf("canonical id of %s: %w", id, err)
	}
	p.canon[id] = c
	return c, nil
}

// build returns the owner's findings from its current matches, or nil when the owner is gone, and
// what Diff needs to tell a withdrawal from a fix. old holds the owner's stored findings: those on
// an image repository that runs a digest not yet catalogued (or with no digest) are carried, since
// that digest's matches are unknown; resolving them would report every rollout as fixed and reopen
// everything once the new digest is catalogued.
func (e *Engine) build(ctx context.Context, p *pass, key string, old []model.Finding) ([]model.Finding, findings.Withdrawals, error) {
	var w findings.Withdrawals
	o, ok, err := e.o.Store.GetOwner(ctx, key)
	if err != nil {
		return nil, w, fmt.Errorf("owner: %w", err)
	}
	if !ok {
		return nil, w, nil
	}
	var digests []string
	uncatalogued := map[string]bool{} // image repositories running a digest that is not catalogued
	for _, c := range o.Containers {
		if c.Digest == "" {
			uncatalogued[c.Repo] = true
		} else if !slices.Contains(digests, c.Digest) {
			digests = append(digests, c.Digest)
		}
	}
	w.Digests = digests
	ms, err := e.o.Store.MatchesForDigests(ctx, digests)
	if err != nil {
		return nil, w, fmt.Errorf("matches: %w", err)
	}
	matched := map[string]bool{}
	var ids []string
	seen := map[string]bool{}
	addID := func(id string) {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	for _, m := range ms {
		matched[m.ImageDigest] = true
		addID(m.AdvisoryID)
	}
	pkgs := map[string]model.Package{}
	users := map[string]string{}
	for _, d := range digests {
		img, ok, err := e.o.Store.GetImage(ctx, d)
		if err != nil {
			return nil, w, fmt.Errorf("image %s: %w", d, err)
		}
		if ok && img.Status == model.ImageCatalogued {
			users[d] = img.ConfigUser
		} else {
			for _, c := range o.Containers {
				if c.Digest == d {
					uncatalogued[c.Repo] = true
				}
			}
		}
		if !matched[d] {
			continue // Build reads the packages of matches only
		}
		ps, err := e.o.Store.PackagesForImage(ctx, d)
		if err != nil {
			return nil, w, fmt.Errorf("packages of %s: %w", d, err)
		}
		for _, pk := range ps {
			pkgs[pk.ID] = pk
		}
	}
	var carry []model.Finding
	for _, f := range old {
		if f.State != model.StateResolved && uncatalogued[f.ImageRepo] {
			carry = append(carry, f)
			addID(f.AdvisoryID)
		}
	}
	advs, err := e.o.Store.Advisories(ctx, ids)
	if err != nil {
		return nil, w, fmt.Errorf("advisories: %w", err)
	}
	r := findings.BuildResult(findings.BuildInput{
		Cluster:        e.o.Config.ClusterName,
		Owner:          o,
		Matches:        ms,
		Packages:       pkgs,
		Advisories:     advs,
		Exceptions:     p.rules,
		GrypeDBBuilds:  p.builds,
		ImageUsers:     users,
		Carry:          carry,
		Now:            p.now,
		PriorityConfig: e.o.Config.Priority,
	})
	w.NotAffected = r.NotAffected
	return r.Findings, w, nil
}

// matchMode is what matchImage runs and whether it stores the result.
type matchMode int

const (
	matchPersist   matchMode = iota // every matcher; store each one's matches
	matchGrype                      // grype alone, with the stored OSV matches as hints; store them
	matchCandidate                  // every matcher; store nothing (upgrade candidates)
)

// matchResult is what matchImage returns.
type matchResult struct {
	matches       []model.Match // of the matchers that succeeded
	grypeNotReady bool          // grype ran with no DB loaded
}

// matchImage runs the matchers of mode over a catalogued digest: the Matchers in order, then grype
// with the OSV matches as hints. With matchPersist and matchGrype it holds matchMu throughout, each
// matcher's matches replace its stored matches on the digest, and observers hear once that the
// digest's matches changed if any did. A grype matcher with no DB loaded has no opinion: its stored
// matches stay and it is not an error (MatchCandidate decides what that means for a candidate). Any
// other failure leaves that matcher's stored matches untouched and is returned, joined, after the
// other matchers have run.
func (e *Engine) matchImage(ctx context.Context, digest string, mode matchMode) (matchResult, error) {
	persist := mode != matchCandidate
	if persist {
		e.matchMu.Lock()
		defer e.matchMu.Unlock()
	}
	var res matchResult
	img, ok, err := e.o.Store.GetImage(ctx, digest)
	if err != nil {
		return res, fmt.Errorf("engine: image %s: %w", digest, err)
	}
	if !ok || img.Status != model.ImageCatalogued {
		return res, nil
	}
	sbom, _, err := e.o.Store.GetSBOM(ctx, digest)
	if err != nil {
		return res, fmt.Errorf("engine: SBOM of %s: %w", digest, err)
	}
	pkgs, err := e.o.Store.PackagesForImage(ctx, digest)
	if err != nil {
		return res, fmt.Errorf("engine: packages of %s: %w", digest, err)
	}
	stored, err := e.o.Store.MatchesForDigests(ctx, []string{digest})
	if err != nil {
		return res, fmt.Errorf("engine: matches of %s: %w", digest, err)
	}
	in := match.ImageInput{Digest: digest, SyftJSON: sbom, Packages: pkgs}
	now := e.now()

	var (
		errs      []error
		osvFailed = mode == matchGrype // grype alone: the OSV matches that stand are the stored ones
		changed   bool
	)
	// run matches with m and, with persist, stores the result. It reports whether m had an opinion.
	run := func(m match.Matcher, in match.ImageInput, grype bool) ([]model.Match, bool) {
		ms, err := m.MatchImage(ctx, in)
		if err != nil {
			if grype && errors.Is(err, match.ErrNotReady) {
				res.grypeNotReady = true
			} else {
				errs = append(errs, fmt.Errorf("engine: %s matcher on %s: %w", m.Source(), digest, err))
			}
			return nil, false
		}
		ms = stampObserved(ms, stored, now)
		if persist {
			scope := store.MatchScope{Source: m.Source(), Digests: []string{digest}}
			affected, err := e.o.Store.ReplaceMatches(ctx, scope, ms)
			if err != nil {
				errs = append(errs, fmt.Errorf("engine: store %s matches of %s: %w", m.Source(), digest, err))
			}
			changed = changed || len(affected) > 0
		}
		res.matches = append(res.matches, ms...)
		return ms, true
	}
	var hints []model.Match
	if mode != matchGrype {
		for _, m := range e.o.Matchers {
			ms, ok := run(m, in, false)
			if !ok && m.Source() == model.SourceOSV {
				osvFailed = true
			}
			hints = append(hints, sourced(ms, model.SourceOSV)...)
		}
	}
	if osvFailed {
		hints = append(hints, sourced(stored, model.SourceOSV)...)
	}
	in.Hints = hints
	run(e.o.Grype, in, true)
	if changed {
		e.matchesReplaced(ctx, []string{digest})
	}
	return res, errors.Join(errs...)
}

// sourced returns the matches of ms from source.
func sourced(ms []model.Match, source model.MatchSource) []model.Match {
	var out []model.Match
	for _, m := range ms {
		if m.Source == source {
			out = append(out, m)
		}
	}
	return out
}

// matchKey identifies a stored match.
type matchKey struct {
	digest, packageID, advisoryID string
	source                        model.MatchSource
}

func keyOf(m model.Match) matchKey {
	return matchKey{m.ImageDigest, m.PackageID, m.AdvisoryID, m.Source}
}

// stampObserved returns a copy of ms in which each match takes the earlier of its own ObservedAt
// (the OSV fast path stamps when ffs observed the record) and that of the stored match with the same
// key, and a match still without one is observed now. It does in memory what ReplaceMatches does on
// write, so the matches matchImage returns (hints, MatchCandidate) carry the stored times: a
// re-match never moves the time ffs first saw a match, which provisional findings and precedence
// count from.
func stampObserved(ms, stored []model.Match, now time.Time) []model.Match {
	if len(ms) == 0 {
		return ms
	}
	seen := make(map[matchKey]time.Time, len(stored))
	for _, m := range stored {
		seen[keyOf(m)] = m.ObservedAt
	}
	out := slices.Clone(ms)
	for i := range out {
		if t, ok := seen[keyOf(out[i])]; ok && !t.IsZero() && (out[i].ObservedAt.IsZero() || t.Before(out[i].ObservedAt)) {
			out[i].ObservedAt = t
		}
		if out[i].ObservedAt.IsZero() {
			out[i].ObservedAt = now
		}
	}
	return out
}
