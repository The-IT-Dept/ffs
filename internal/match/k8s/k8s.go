// Package k8s matches the cluster-level subjects ffs inventories: the Kubernetes version and each
// container runtime version, as the synthetic digests "k8s:<version>" and "runtime:<name>@<version>".
// Kubernetes is matched against OSV GIT records for the kubernetes repository, containerd and CRI-O
// against OSV Go module records. Findings are per cluster, never per node.
package k8s

import (
	"context"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/go-logr/logr"
	"github.com/ossf/osv-schema/bindings/go/osvschema"

	"github.com/the-it-dept/ffs/internal/feeds/osv"
	"github.com/the-it-dept/ffs/internal/match"
	"github.com/the-it-dept/ffs/internal/match/osvfast"
	"github.com/the-it-dept/ffs/internal/match/upstream"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

// Repo is the OSV GIT repository of Kubernetes. Wiring adds it to the OSV feed's GitRepos.
const Repo = "github.com/kubernetes/kubernetes"

// The Go modules of the container runtimes.
const (
	ContainerdV1 = "github.com/containerd/containerd"
	ContainerdV2 = "github.com/containerd/containerd/v2"
	CRIO         = "github.com/cri-o/cri-o"
)

var runtimeModules = []string{ContainerdV1, ContainerdV2, CRIO}

// runtimeVersion extracts the numeric version of a runtime, dropping any "v" prefix and vendor suffix.
var runtimeVersion = regexp.MustCompile(`^v?(\d+\.\d+\.\d+)`)

// Matcher matches the synthetic Kubernetes and container-runtime digests. It is safe for concurrent
// use.
type Matcher struct{ st *store.Store }

var (
	_ match.Matcher       = (*Matcher)(nil)
	_ match.RecordMatcher = (*Matcher)(nil)
)

// New returns a matcher over the OSV records cached in st.
func New(st *store.Store) *Matcher { return &Matcher{st: st} }

// Source implements match.Matcher.
func (m *Matcher) Source() model.MatchSource { return model.SourceK8s }

// subject is a parsed synthetic digest.
type subject struct {
	digest  string
	version string // numeric version without "v"
	module  string // Go module for a runtime; empty for Kubernetes
}

// parse reads a synthetic digest. ok is false for anything else, or a runtime version without a
// numeric major.minor.patch.
func parse(digest string) (s subject, ok bool) {
	s = subject{digest: digest}
	switch {
	case strings.HasPrefix(digest, "k8s:"):
		s.version = strings.TrimPrefix(strings.TrimPrefix(digest, "k8s:"), "v")
		return s, s.version != ""
	case strings.HasPrefix(digest, "runtime:"):
		name, v, found := strings.Cut(strings.TrimPrefix(digest, "runtime:"), "@")
		if !found {
			return s, false
		}
		sub := runtimeVersion.FindStringSubmatch(v)
		if sub == nil {
			return s, false
		}
		s.version = sub[1]
		switch name {
		case "containerd":
			s.module = ContainerdV1
			if major, _, _ := strings.Cut(s.version, "."); major != "0" && major != "1" {
				s.module = ContainerdV2
			}
		case "cri-o":
			s.module = CRIO
		default:
			return s, false
		}
		return s, true
	}
	return s, false
}

// MatchImage implements match.Matcher. Digests that are not synthetic, and synthetic ones without
// a package, get no matches.
func (m *Matcher) MatchImage(ctx context.Context, in match.ImageInput) ([]model.Match, error) {
	s, ok := parse(in.Digest)
	if !ok || len(in.Packages) == 0 {
		return nil, nil
	}
	bucket, name := osv.BucketGIT, Repo
	if s.module != "" {
		bucket, name = osv.BucketGo, s.module
	}
	ids, err := m.st.OSVRecordIDsByName(ctx, bucket, []string{name})
	if err != nil {
		return nil, err
	}
	recs, err := m.records(ctx, ids, nil)
	if err != nil {
		return nil, err
	}
	var ms matchSet
	for _, v := range recs {
		if err := m.eval(ctx, &ms, s, in.Packages[0].ID, v); err != nil {
			return nil, err
		}
	}
	return ms.list, nil
}

// ApplyOSV implements match.RecordMatcher. GIT records with a range in Repo and Go records for the
// runtime modules have their advisory stored. Each advisory then gets one Delta, scoped to the k8s
// source and that advisory, evaluated against every synthetic digest in use. Unreadable records are
// skipped; only store failures are errors.
func (m *Matcher) ApplyOSV(ctx context.Context, recs []osv.Changed) ([]match.Delta, error) {
	log := logr.FromContextOrDiscard(ctx)
	changed := map[string]*osvschema.Vulnerability{}
	for _, r := range recs {
		if r.Ecosystem != osv.BucketGIT && r.Ecosystem != osv.BucketGo {
			continue
		}
		v, err := match.ParseOSV(r.Raw)
		if err != nil || v.GetId() == "" {
			log.V(1).Info("skipping an unreadable OSV record", "bucket", r.Ecosystem, "id", r.ID, "error", err)
			continue
		}
		if !relevant(r.Ecosystem, v) {
			continue
		}
		if _, err := match.UpsertOSVAdvisory(ctx, m.st, v); err != nil {
			return nil, err
		}
		changed[v.GetId()] = v
	}
	// Resolve canonicals once every record is stored: a later record can merge an earlier one's
	// advisory into another.
	byAdv := map[string]map[string]*osvschema.Vulnerability{}
	for id, v := range changed {
		adv, err := m.st.Canonical(ctx, id)
		if err != nil {
			return nil, err
		}
		if byAdv[adv] == nil {
			byAdv[adv] = map[string]*osvschema.Vulnerability{}
		}
		byAdv[adv][id] = v
	}
	if len(byAdv) == 0 {
		return nil, nil
	}
	subjects, err := m.subjects(ctx)
	if err != nil {
		return nil, err
	}
	deltas := make([]match.Delta, 0, len(byAdv))
	for _, adv := range slices.Sorted(maps.Keys(byAdv)) {
		ids, err := match.AdvisoryRecordIDs(ctx, m.st, adv)
		if err != nil {
			return nil, err
		}
		all, err := m.records(ctx, ids, byAdv[adv])
		if err != nil {
			return nil, err
		}
		d := match.Delta{Scope: store.MatchScope{Source: model.SourceK8s, AdvisoryIDs: []string{adv}}}
		var ms matchSet
		for _, sp := range subjects {
			for _, v := range all {
				if err := m.eval(ctx, &ms, sp.subject, sp.packageID, v); err != nil {
					return nil, err
				}
			}
		}
		d.Matches = ms.list
		deltas = append(deltas, d)
	}
	return deltas, nil
}

type storedSubject struct {
	subject
	packageID string
}

// subjects returns the synthetic digests in use with the ID of their package.
func (m *Matcher) subjects(ctx context.Context) ([]storedSubject, error) {
	digests, err := m.st.DigestsInUse(ctx)
	if err != nil {
		return nil, err
	}
	var out []storedSubject
	for _, d := range digests {
		s, ok := parse(d)
		if !ok {
			continue
		}
		pkgs, err := m.st.PackagesForImage(ctx, d)
		if err != nil {
			return nil, err
		}
		if len(pkgs) == 0 {
			continue
		}
		out = append(out, storedSubject{subject: s, packageID: pkgs[0].ID})
	}
	return out, nil
}

// relevant reports whether v, handed off from bucket, concerns Kubernetes or a runtime module.
func relevant(bucket string, v *osvschema.Vulnerability) bool {
	for _, a := range v.GetAffected() {
		switch bucket {
		case osv.BucketGIT:
			for _, r := range a.GetRanges() {
				if r.GetType() == osvschema.Range_GIT && osv.NormalizeRepo(r.GetRepo()) == Repo {
					return true
				}
			}
		case osv.BucketGo:
			if slices.Contains(runtimeModules, a.GetPackage().GetName()) {
				return true
			}
		}
	}
	return false
}

// eval adds the match of record v for subject s, if any.
func (m *Matcher) eval(ctx context.Context, ms *matchSet, s subject, packageID string, v *osvschema.Vulnerability) error {
	var (
		hit   bool
		fs    model.FixState
		fixed []string
		ns    string
	)
	if s.module == "" {
		hit, fs, fixed = upstream.MatchGitRecord(v, Repo, []string{"v" + s.version}, s.version)
		ns = "git:" + Repo
	} else {
		ns = "go:" + s.module
		for _, a := range v.GetAffected() {
			if a.GetPackage().GetName() != s.module {
				continue
			}
			ok, f, fx, err := osvfast.Evaluate(a, s.version)
			if err != nil {
				logr.FromContextOrDiscard(ctx).V(1).Info("skipping an unevaluable OSV range", "id", v.GetId(), "version", s.version, "error", err.Error())
				continue
			}
			if ok {
				hit, fs, fixed = true, f, fx
				break
			}
		}
	}
	if !hit || v.GetWithdrawn() != nil {
		return nil
	}
	adv, err := m.st.Canonical(ctx, v.GetId())
	if err != nil {
		return err
	}
	ms.add(model.Match{
		ImageDigest:   s.digest,
		PackageID:     packageID,
		AdvisoryID:    adv,
		Source:        model.SourceK8s,
		FixState:      fs,
		FixedVersions: fixed,
		Namespace:     ns,
	})
	return nil
}

// records returns the cached records with ids, with override replacing (or adding) records by id,
// sorted by id. Cached records that do not parse are skipped.
func (m *Matcher) records(ctx context.Context, ids []string, override map[string]*osvschema.Vulnerability) ([]*osvschema.Vulnerability, error) {
	raws, err := m.st.OSVRecordsByID(ctx, ids)
	if err != nil {
		return nil, err
	}
	byID := maps.Clone(override)
	if byID == nil {
		byID = map[string]*osvschema.Vulnerability{}
	}
	for _, raw := range raws {
		v, err := match.ParseOSV(raw)
		if err != nil {
			logr.FromContextOrDiscard(ctx).V(1).Info("skipping an unreadable cached OSV record", "error", err.Error())
			continue
		}
		if _, ok := byID[v.GetId()]; !ok {
			byID[v.GetId()] = v
		}
	}
	out := make([]*osvschema.Vulnerability, 0, len(byID))
	for _, id := range slices.Sorted(maps.Keys(byID)) {
		out = append(out, byID[id])
	}
	return out, nil
}

// matchSet collects matches, one per digest and advisory. When two records of one advisory both
// match, the one with a fixed version wins.
type matchSet struct {
	list []model.Match
	at   map[[2]string]int
}

func (s *matchSet) add(m model.Match) {
	k := [2]string{m.ImageDigest, m.AdvisoryID}
	i, ok := s.at[k]
	if !ok {
		if s.at == nil {
			s.at = map[[2]string]int{}
		}
		s.at[k] = len(s.list)
		s.list = append(s.list, m)
		return
	}
	if cur := &s.list[i]; cur.FixState != model.FixFixed && m.FixState == model.FixFixed {
		*cur = m
	}
}
