package match

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

// maxTitleRunes bounds a title taken from a record's details.
const maxTitleRunes = 200

// ParseOSV decodes an OSV record. Fields and enum values the schema bindings do not know are
// ignored, so newer records still parse.
func ParseOSV(raw []byte) (*osvschema.Vulnerability, error) {
	v := &osvschema.Vulnerability{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw, v); err != nil {
		return nil, fmt.Errorf("match: osv record: %w", err)
	}
	return v, nil
}

// UpsertOSVAdvisory stores the advisory of an OSV record and returns its canonical id. The record's
// candidate ids are its own id, its aliases and, when its upstream names exactly one CVE, that CVE;
// the advisory is keyed by model.CanonicalID over them, with the rest as aliases. The id returned is
// store.Canonical of the record id, because aliases stored earlier can make a different id canonical.
func UpsertOSVAdvisory(ctx context.Context, st *store.Store, v *osvschema.Vulnerability) (string, error) {
	cands := candidateIDs(v)
	canon := model.CanonicalID(cands...)
	a := model.Advisory{
		ID:        canon,
		Aliases:   slices.DeleteFunc(slices.Clone(cands), func(id string) bool { return id == canon }),
		Title:     osvTitle(v),
		Published: osvTime(v.GetPublished()),
		Modified:  osvTime(v.GetModified()),
		Malicious: slices.ContainsFunc(cands, func(id string) bool { return strings.HasPrefix(id, "MAL-") }),
		Withdrawn: v.GetWithdrawn() != nil,
	}
	for _, r := range v.GetReferences() {
		if u := r.GetUrl(); u != "" && !slices.Contains(a.Links, u) {
			a.Links = append(a.Links, u)
		}
	}
	if err := st.UpsertAdvisory(ctx, a); err != nil {
		return "", err
	}
	return st.Canonical(ctx, v.GetId())
}

// AdvisoryRecordIDs returns the canonical id and every stored alias of the advisory: the ids its
// OSV records can be cached under.
func AdvisoryRecordIDs(ctx context.Context, st *store.Store, canonical string) ([]string, error) {
	ids := []string{canonical}
	a, ok, err := st.GetAdvisory(ctx, canonical)
	if err != nil {
		return nil, err
	}
	if ok {
		ids = append(ids, a.Aliases...)
	}
	slices.Sort(ids)
	return slices.Compact(ids), nil
}

// candidateIDs returns the record id first, then its aliases, then the single CVE its upstream
// names, if it names exactly one; empty and repeated ids are dropped.
func candidateIDs(v *osvschema.Vulnerability) []string {
	ids := []string{v.GetId()}
	ids = append(ids, v.GetAliases()...)
	var upstreamCVEs []string
	for _, u := range v.GetUpstream() {
		if strings.HasPrefix(u, "CVE-") {
			upstreamCVEs = append(upstreamCVEs, u)
		}
	}
	if len(upstreamCVEs) == 1 {
		ids = append(ids, upstreamCVEs[0])
	}
	out := ids[:0]
	for _, id := range ids {
		if id != "" && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}

// osvTitle returns the record's summary, or else the first line of its details cut to 200 runes.
func osvTitle(v *osvschema.Vulnerability) string {
	if s := strings.TrimSpace(v.GetSummary()); s != "" {
		return s
	}
	line, _, _ := strings.Cut(strings.TrimSpace(v.GetDetails()), "\n")
	line = strings.TrimSpace(line)
	if utf8.RuneCountInString(line) <= maxTitleRunes {
		return line
	}
	return strings.TrimSpace(string([]rune(line)[:maxTitleRunes]))
}

// osvTime returns ts as a UTC time, or the zero time when ts is unset.
func osvTime(ts *timestamppb.Timestamp) time.Time {
	if ts == nil {
		return time.Time{}
	}
	return ts.AsTime().UTC()
}
