package crds

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strconv"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/the-it-dept/ffs/api/v1alpha1"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/upgrade"
)

// maxTopOwners is how many affected owners a Vulnerability lists; the full list is in the API.
const maxTopOwners = 50

// findingStatus maps an open finding, its owner and its advisory to a Finding status. owner and
// adv are zero when the store no longer holds them.
func findingStatus(cluster string, f model.Finding, owner model.Owner, adv model.Advisory) v1alpha1.FindingStatus {
	st := v1alpha1.FindingStatus{
		Cluster:     cluster,
		Fingerprint: f.Fingerprint,
		Subject: v1alpha1.FindingSubject{
			Owner:           v1alpha1.OwnerReference{Kind: f.Owner.Kind, Namespace: f.Owner.Namespace, Name: f.Owner.Name, UID: f.Owner.UID},
			Containers:      containersFor(owner, f.ImageRepo),
			ImageRepository: f.ImageRepo,
			Digests:         f.Digests,
		},
		Advisory: v1alpha1.AdvisorySummary{
			ID:             f.AdvisoryID,
			Aliases:        adv.Aliases,
			Title:          adv.Title,
			Severity:       f.Severity.String(),
			SeveritySource: f.SeveritySource,
			Links:          adv.Links,
		},
		Fix:      string(f.FixState),
		Priority: f.Priority.String(),
		Reasons:  f.Reasons,
		Exposure: v1alpha1.ExposureSummary{
			Exposed:                owner.Context.Exposed,
			ExposurePaths:          owner.Context.ExposurePaths,
			Privileged:             owner.Context.Privileged,
			PrivilegeReasons:       owner.Context.PrivilegeReasons,
			PowerfulServiceAccount: owner.Context.PowerfulSA,
			ServiceAccountReasons:  owner.Context.SAReasons,
		},
		Suggestion:  suggestionSummary(f.Suggestion),
		State:       string(f.State),
		Provisional: f.Provisional,
		GoStdlib:    f.GoStdlib,
		Published:   metaTime(f.Published),
		Observed:    metaTime(f.Observed),
		Matched:     metaTime(f.Matched),
		LastSeen:    metaTime(f.LastSeen),
	}
	if m := owner.ManagedBy; m != nil {
		st.Subject.ManagedBy = &v1alpha1.ManagedBy{Tool: m.Tool, Name: m.Name, Namespace: m.Namespace}
	}
	for _, p := range f.Packages {
		st.Packages = append(st.Packages, v1alpha1.AffectedPackage{Name: p.Name, Type: p.Ecosystem, Installed: p.Installed,
			Fixed: p.Fixed, Path: p.Path})
	}
	if len(f.Packages) > 0 && len(f.Packages[0].Fixed) > 0 {
		st.Fix = f.Packages[0].Fixed[0]
	}
	return st
}

// containersFor returns the names of the owner's containers running repo, without repeats.
func containersFor(owner model.Owner, repo string) []string {
	var names []string
	for _, c := range owner.Containers {
		if c.Repo == repo && !slices.Contains(names, c.Name) {
			names = append(names, c.Name)
		}
	}
	return names
}

// suggestionSummary maps an upgrade suggestion; nil when there is none or no tier fixes anything.
// Its Target is upgrade.Target, as the Events and alerts name it: "nginx:1.30.7",
// "nginx:1.30.6 (new digest)" for a refresh, "kubernetes v1.35.10" for the cluster.
func suggestionSummary(s *model.Suggestion) *v1alpha1.SuggestionSummary {
	if s == nil || s.Tier == model.TierNone {
		return nil
	}
	return &v1alpha1.SuggestionSummary{
		Target:     upgrade.Target(*s),
		Digest:     s.ToDigest,
		Tier:       string(s.Tier),
		Fixes:      priorityCounts(s.Fixes),
		Remaining:  priorityCounts(s.Remaining),
		Introduces: priorityCounts(s.Introduces),
	}
}

// priorityCounts keys counts by priority name; nil when there are none.
func priorityCounts(m map[model.Priority]int) map[string]int32 {
	var out map[string]int32
	for p, n := range m {
		if p.String() == "" {
			continue
		}
		if out == nil {
			out = map[string]int32{}
		}
		out[p.String()] = int32(n)
	}
	return out
}

// vulnerabilityStatus summarises an advisory over every open finding on it (open must be
// non-empty), at any priority.
func vulnerabilityStatus(id string, adv model.Advisory, open []model.Finding) v1alpha1.VulnerabilityStatus {
	st := v1alpha1.VulnerabilityStatus{
		ID:             id,
		Aliases:        adv.Aliases,
		Title:          adv.Title,
		Links:          adv.Links,
		CVSS:           decimal(adv.CNACVSS),
		KEV:            adv.KEVAdded != nil,
		EPSS:           decimal(adv.EPSS),
		EPSSPercentile: decimal(adv.EPSSPercentile),
		Published:      metaTime(adv.Published),
		Observed:       metaTime(adv.Observed),
	}
	if adv.KEVAdded != nil {
		st.KEVDateAdded = metaTime(*adv.KEVAdded)
	}
	worst := open[0]
	highest := model.PriorityNone
	byOwner := map[string]v1alpha1.AffectedOwner{}
	ranks := map[string]model.Priority{}
	for _, f := range open {
		st.FixAvailable = st.FixAvailable || f.FixAvailable
		highest = max(highest, f.Priority)
		if f.Severity > worst.Severity {
			worst = f
		}
		k := f.Owner.Key()
		if p, ok := ranks[k]; !ok || f.Priority > p {
			ranks[k] = f.Priority
			byOwner[k] = v1alpha1.AffectedOwner{Kind: f.Owner.Kind, Namespace: f.Owner.Namespace, Name: f.Owner.Name,
				Priority: f.Priority.String()}
		}
	}
	st.Severity = worst.Severity.String()
	st.SeveritySource = worst.SeveritySource
	st.HighestPriority = highest.String()
	st.AffectedOwners = int32(len(byOwner))

	keys := make([]string, 0, len(byOwner))
	for k := range byOwner {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b string) int { return cmp.Or(cmp.Compare(ranks[b], ranks[a]), cmp.Compare(a, b)) })
	for _, k := range keys[:min(len(keys), maxTopOwners)] {
		st.TopOwners = append(st.TopOwners, byOwner[k])
	}
	return st
}

// findingHash is the content hash of a Finding status. LastSeen counts only to the UTC day, so
// liveness alone rewrites a Finding at most once a day.
func findingHash(st v1alpha1.FindingStatus) string {
	if st.LastSeen != nil {
		st.LastSeen = &metav1.Time{Time: st.LastSeen.Truncate(24 * time.Hour)}
	}
	return contentHash(st)
}

// contentHash is the hex sha256 of v's JSON encoding.
func contentHash(v any) string {
	b, _ := json.Marshal(v) // statuses are plain data: strings, numbers, times and string-keyed maps
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// metaTime returns nil for the zero time.
func metaTime(t time.Time) *metav1.Time {
	if t.IsZero() {
		return nil
	}
	mt := metav1.NewTime(t)
	return &mt
}

// decimal renders a score as a decimal string, "" when it is zero (not known).
func decimal(v float64) string {
	if v == 0 {
		return ""
	}
	return strconv.FormatFloat(v, 'f', -1, 64)
}
