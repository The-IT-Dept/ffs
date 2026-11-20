// Package openreports writes one OpenReports Report per workload owner, and optionally a
// wgpolicyk8s PolicyReport mirror, so Policy Reporter users see ffs findings.
package openreports

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	orv1alpha1 "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/the-it-dept/ffs/internal/model"
)

const (
	// Source is the report source and result source for everything ffs writes.
	Source = "ffs"
	// LabelManagedBy marks the reports ffs owns.
	LabelManagedBy = "app.kubernetes.io/managed-by"
	// AnnotationOwner records the owner key a report describes.
	AnnotationOwner = "ffs.theitdept.au/owner"
	// AnnotationContentHash is the hash of the report content, used to skip no-op writes.
	AnnotationContentHash = "ffs.theitdept.au/content-hash"

	maxNameLen = 63
	nameKeep   = 54
)

// ReportName returns the DNS-label-safe Report name for owner o.
func ReportName(o model.OwnerRef) string {
	raw := strings.ToLower("ffs-" + o.Kind + "-" + o.Name)
	changed := false
	b := []byte(raw)
	for i, c := range b {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			continue
		}
		b[i] = '-'
		changed = true
	}
	name := string(b)
	if !changed && len(name) <= maxNameLen {
		return name
	}
	if len(name) > nameKeep {
		name = name[:nameKeep]
	}
	name = strings.TrimRight(name, "-")
	sum := sha256.Sum256([]byte(o.Key()))
	return name + "-" + hex.EncodeToString(sum[:])[:8]
}

// BuildReport builds the Report for owner o from its open findings. It returns false when no
// finding is at least medium priority. ns is the namespace for owners that have none.
func BuildReport(o model.Owner, fs []model.Finding, advs map[string]model.Advisory, maxResults int, ns string) (*orv1alpha1.Report, bool) {
	var q []model.Finding
	for _, f := range fs {
		if f.Priority >= model.PriorityMedium {
			q = append(q, f)
		}
	}
	if len(q) == 0 {
		return nil, false
	}
	sort.SliceStable(q, func(i, j int) bool {
		a, b := q[i], q[j]
		if a.Priority != b.Priority {
			return a.Priority > b.Priority
		}
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.AdvisoryID != b.AdvisoryID {
			return a.AdvisoryID < b.AdvisoryID
		}
		return a.ImageRepo < b.ImageRepo
	})

	var sum orv1alpha1.ReportSummary
	for _, f := range q {
		if f.Priority >= model.PriorityHigh {
			sum.Fail++
		} else {
			sum.Warn++
		}
	}
	if maxResults > 0 && len(q) > maxResults {
		q = q[:maxResults]
	}
	results := make([]orv1alpha1.ReportResult, 0, len(q))
	for _, f := range q {
		results = append(results, buildResult(f, advs[f.AdvisoryID]))
	}

	r := &orv1alpha1.Report{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ReportName(o.Ref),
			Namespace: o.Ref.Namespace,
			Labels:    map[string]string{LabelManagedBy: "ffs"},
			Annotations: map[string]string{
				AnnotationOwner: o.Ref.Key(),
			},
		},
		Source: Source,
		Configuration: &orv1alpha1.ReportConfiguration{Limits: orv1alpha1.Limits{
			MaxResults:   maxResults,
			StatusFilter: []orv1alpha1.StatusFilter{"fail", "warn"},
		}},
		Summary: sum,
		Results: results,
	}
	if r.Namespace == "" {
		r.Namespace = ns
	}
	if av, ok := o.Ref.ObjectAPIVersion(); ok {
		r.Scope = &corev1.ObjectReference{APIVersion: av, Kind: o.Ref.Kind, Namespace: o.Ref.Namespace,
			Name: o.Ref.Name, UID: types.UID(o.Ref.UID)}
	}
	r.Annotations[AnnotationContentHash] = contentHash(r)
	return r, true
}

func contentHash(r *orv1alpha1.Report) string {
	b, _ := json.Marshal(struct {
		Scope         *corev1.ObjectReference
		Summary       orv1alpha1.ReportSummary
		Results       []orv1alpha1.ReportResult
		Configuration *orv1alpha1.ReportConfiguration
	}{r.Scope, r.Summary, r.Results, r.Configuration}) //nolint:errchkjson // plain structs of strings and ints cannot fail to marshal
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func buildResult(f model.Finding, adv model.Advisory) orv1alpha1.ReportResult {
	res := orv1alpha1.Result("warn")
	if f.Priority >= model.PriorityHigh {
		res = "fail"
	}
	desc := adv.Title
	if desc == "" {
		desc = f.AdvisoryID
	}
	rr := orv1alpha1.ReportResult{
		Source:      Source,
		Policy:      f.AdvisoryID,
		Rule:        f.ImageRepo,
		Category:    "Vulnerability",
		Severity:    resultSeverity(f.Severity),
		Timestamp:   metav1.Timestamp{Seconds: f.Matched.Unix()},
		Result:      res,
		Description: desc,
		Properties:  properties(f, adv),
	}
	return rr
}

func resultSeverity(s model.Severity) orv1alpha1.ResultSeverity {
	switch s {
	case model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow:
		return orv1alpha1.ResultSeverity(s.String())
	}
	return "info"
}

func properties(f model.Finding, adv model.Advisory) map[string]string {
	p := map[string]string{}
	set := func(k, v string) {
		if v != "" {
			p[k] = v
		}
	}
	var names, installed, fixed []string
	for _, pk := range f.Packages {
		names = append(names, pk.Name)
		installed = append(installed, pk.Installed)
		if len(pk.Fixed) > 0 {
			fixed = append(fixed, pk.Fixed[0])
		}
	}
	set("resource", strings.Join(names, ", "))
	set("installedVersion", strings.Join(installed, ", "))
	set("fixedVersion", strings.Join(fixed, ", "))
	if len(adv.Links) > 0 {
		set("primaryLink", adv.Links[0])
	}
	if adv.CNACVSS > 0 {
		set("score", fmt.Sprintf("%.1f", adv.CNACVSS))
	}
	set("ffs.priority", f.Priority.String())
	set("ffs.reasons", strings.Join(f.Reasons, "; "))
	if s := f.Suggestion; s != nil && s.Tier != model.TierNone && s.ToTag != "" {
		set("ffs.suggestedImage", s.Repo+":"+s.ToTag)
	}
	return p
}
