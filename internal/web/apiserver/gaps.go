package apiserver

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/the-it-dept/ffs/internal/inventory"
	"github.com/the-it-dept/ffs/internal/match/upstream"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
	"github.com/the-it-dept/ffs/internal/web/apigen"
)

// imageGaps lists what ffs cannot see in an image: why it is not catalogued, or, for a catalogued
// image, each coverage note in order (attestation-only SBOM, unattributed executables, Rust without
// cargo-auditable, classifier-found packages matched daily against CPE data only). cpeOnly are the
// names of those packages. A digest with no images row is pending.
func imageGaps(img model.Image, hasRow bool, cpeOnly []string) []apigen.GapCode {
	if !hasRow || img.Status == model.ImagePending {
		return []apigen.GapCode{apigen.GapCodePending}
	}
	switch img.Status {
	case model.ImageUnresolvable:
		return []apigen.GapCode{unresolvableGap(img.StatusReason)}
	case model.ImageCatalogFailed:
		return []apigen.GapCode{apigen.GapCodeCatalogFailed}
	case model.ImagePending, model.ImageCatalogued:
	}
	out := []apigen.GapCode{}
	if img.Source == "attestation" {
		out = append(out, apigen.GapCodeAttestationPartial)
	}
	if img.Coverage.UnattributedELF > 0 {
		out = append(out, apigen.GapCodeUnattributedExecutables)
	}
	if img.Coverage.RustWithoutAuditable > 0 {
		out = append(out, apigen.GapCodeRustNoAuditable)
	}
	if len(cpeOnly) > 0 {
		out = append(out, apigen.GapCodeCpeOnlyClassifier)
	}
	return out
}

// unresolvableGap classifies why an image could not be resolved, by the inventory's reading of its
// status reason (inventory.ClassifyUnresolvable).
func unresolvableGap(reason string) apigen.GapCode {
	return unresolvableGaps[inventory.ClassifyUnresolvable(reason)]
}

// unresolvableGaps is the gap code of each unresolvable class.
var unresolvableGaps = map[model.UnresolvableClass]apigen.GapCode{
	model.UnresolvableAuth:            apigen.GapCodeUnresolvableAuth,
	model.UnresolvableSideLoaded:      apigen.GapCodeUnresolvableSideloaded,
	model.UnresolvableNotFound:        apigen.GapCodeUnresolvableNotfound,
	model.UnresolvableUnreachable:     apigen.GapCodeUnresolvableUnreachable,
	model.UnresolvableLayersDiscarded: apigen.GapCodeLayersDiscarded,
	model.UnresolvableOther:           apigen.GapCodeUnresolvableOther,
}

// gapRemedy is what to do about each gap, as a code; the words live in the UI and the docs.
var gapRemedy = map[apigen.GapCode]apigen.RemedyCode{
	apigen.GapCodePending:                 apigen.RemedyCodeWait,
	apigen.GapCodeUnresolvableAuth:        apigen.RemedyCodeAddPullSecret,
	apigen.GapCodeUnresolvableSideloaded:  apigen.RemedyCodeEnableNodeAgent,
	apigen.GapCodeUnresolvableNotfound:    apigen.RemedyCodeEnableNodeAgent,
	apigen.GapCodeUnresolvableUnreachable: apigen.RemedyCodeCheckNetwork,
	apigen.GapCodeUnresolvableOther:       apigen.RemedyCodeCheckReference,
	apigen.GapCodeLayersDiscarded:         apigen.RemedyCodeRepullImage,
	apigen.GapCodeCatalogFailed:           apigen.RemedyCodeRetryLater,
	apigen.GapCodeAttestationPartial:      apigen.RemedyCodeInformational,
	apigen.GapCodeUnattributedExecutables: apigen.RemedyCodeInformational,
	apigen.GapCodeRustNoAuditable:         apigen.RemedyCodeBuildWithAuditable,
	apigen.GapCodeCpeOnlyClassifier:       apigen.RemedyCodeInformational,
	apigen.GapCodeNodeAgentMissing:        apigen.RemedyCodeEnableNodeAgent,
	apigen.GapCodeNodeAgentBlocked:        apigen.RemedyCodeCheckHostPermissions,
	apigen.GapCodeNoPackageDatabase:       apigen.RemedyCodeInformational,
	apigen.GapCodeContentStoreUnreadable:  apigen.RemedyCodeInformational,
	apigen.GapCodeHostNotInventoried:      apigen.RemedyCodeCheckNodeAgent,
	apigen.GapCodeNodeAgentUnsupported:    apigen.RemedyCodeInformational,
	apigen.GapCodeFeedStale:               apigen.RemedyCodeCheckFeedAccess,
}

// maxGapDetail bounds a gap's detail, in characters.
const maxGapDetail = 200

// scopeGaps lists what ffs cannot see in a scope:
//   - one gap per stale feed, in every scope;
//   - one gap per code and image, for the in-use container images of a cluster, namespace or
//     workload scope that are not seen into in full detail, or for the image of an image scope;
//   - one gap per code over the nodes of a cluster, node group or node scope, from their agents.
//
// Stale feeds come first, then the gaps affecting the most workloads, then the most nodes, then by
// code and target.
func (s *Server) scopeGaps(ctx context.Context, sc model.Scope) ([]apigen.Gap, error) {
	gaps := []apigen.Gap{}
	states, err := s.feedStates(ctx)
	if err != nil {
		return nil, err
	}
	now := s.o.Now()
	for i, st := range states {
		if stale(st, s.o.Feeds[i], now) {
			gaps = append(gaps, apigen.Gap{Code: apigen.GapCodeFeedStale, Remedy: gapRemedy[apigen.GapCodeFeedStale], What: st.Name,
				Detail: trimDetail(st.LastError)})
		}
	}
	images, err := s.gapImages(ctx, sc)
	if err != nil {
		return nil, err
	}
	digests := make([]string, len(images))
	for i, c := range images {
		digests[i] = c.Image.Digest
	}
	classified, err := s.o.Store.ClassifiedPackages(ctx, digests)
	if err != nil {
		return nil, err
	}
	for _, c := range images {
		img := c.Image
		cpeOnly := upstream.UncoveredClassified(classified[img.Digest])
		what := cmp.Or(img.Repo, img.Digest)
		target := scopeRef(model.Scope{Kind: model.ScopeImage, Value: img.Digest}, what)
		for _, code := range imageGaps(img, c.HasRow, cpeOnly) {
			detail := ""
			switch {
			case code == apigen.GapCodeCpeOnlyClassifier:
				detail = strings.Join(cpeOnly, ", ")
			case img.Status == model.ImageUnresolvable || img.Status == model.ImageCatalogFailed:
				detail = img.StatusReason
			}
			gaps = append(gaps, apigen.Gap{Code: code, Remedy: gapRemedy[code], What: what, Detail: trimDetail(detail), Target: &target,
				Affects: apigen.GapAffects{Workloads: len(c.Owners), Images: 1}})
		}
	}
	nodeGaps, err := s.nodeGaps(ctx, sc)
	if err != nil {
		return nil, err
	}
	gaps = append(gaps, nodeGaps...)
	slices.SortStableFunc(gaps, func(a, b apigen.Gap) int {
		if fa, fb := a.Code == apigen.GapCodeFeedStale, b.Code == apigen.GapCodeFeedStale; fa != fb {
			if fa {
				return -1
			}
			return 1
		}
		return cmp.Or(cmp.Compare(b.Affects.Workloads, a.Affects.Workloads), cmp.Compare(b.Affects.Nodes, a.Affects.Nodes),
			cmp.Compare(a.Code, b.Code), cmp.Compare(targetLabel(a), targetLabel(b)))
	})
	return gaps, nil
}

// coveredClassifiers are the classifier-found packages the upstream map covers, which the store's
// gap tally does not count as cpe_only_classifier gaps.
var coveredClassifiers = upstream.Covered()

// scopeGapCount is len(scopeGaps(sc)), counted without listing the gaps: the stale feeds, the image
// gaps from the store's tally (the scope's images are never read one by one), and the node gaps.
func (s *Server) scopeGapCount(ctx context.Context, sc model.Scope) (int, error) {
	states, err := s.feedStates(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	now := s.o.Now()
	for i, st := range states {
		if stale(st, s.o.Feeds[i], now) {
			n++
		}
	}
	switch sc.Kind {
	case model.ScopeCluster, model.ScopeNamespace, model.ScopeWorkload:
		t, err := s.o.Store.ImageGapTally(ctx, sc, coveredClassifiers)
		if err != nil {
			return 0, err
		}
		n += t.Codes + t.Uncovered
	case model.ScopeImage:
		images, err := s.gapImages(ctx, sc)
		if err != nil {
			return 0, err
		}
		for _, c := range images {
			classified, err := s.o.Store.ClassifiedPackages(ctx, []string{c.Image.Digest})
			if err != nil {
				return 0, err
			}
			n += len(imageGaps(c.Image, c.HasRow, upstream.UncoveredClassified(classified[c.Image.Digest])))
		}
	case model.ScopeNodeGroup, model.ScopeNode, model.ScopeControlPlane:
	}
	nodeGaps, err := s.nodeGaps(ctx, sc)
	if err != nil {
		return 0, err
	}
	return n + len(nodeGaps), nil
}

func targetLabel(g apigen.Gap) string {
	if g.Target == nil {
		return g.What
	}
	return g.Target.Label
}

// gapImages are the images whose gaps a scope lists: the in-use container images of a cluster,
// namespace or workload scope not seen into in full detail, or the image of an image scope when it
// is not; none for the other scopes.
func (s *Server) gapImages(ctx context.Context, sc model.Scope) ([]store.CoverageImage, error) {
	switch sc.Kind {
	case model.ScopeCluster, model.ScopeNamespace, model.ScopeWorkload:
		return s.o.Store.CoverageImages(ctx, sc)
	case model.ScopeImage:
		img, hasRow, owners, err := s.imageOf(ctx, sc.Value)
		if err != nil {
			return nil, err
		}
		if hasRow && store.CoverageClassOf(img) == model.CoverageFull {
			return nil, nil
		}
		return []store.CoverageImage{{Image: img, Owners: owners, HasRow: hasRow}}, nil
	case model.ScopeNodeGroup, model.ScopeNode, model.ScopeControlPlane:
	}
	return nil, nil
}

// nodeGaps groups the coverage gaps of a cluster's, node group's or node's nodes by code: the
// nodes affected, the one node as the target when only one is, and the detail of the first node by
// name. Other scopes have none.
func (s *Server) nodeGaps(ctx context.Context, sc model.Scope) ([]apigen.Gap, error) {
	var nodes []string // nil: every stored node
	switch sc.Kind {
	case model.ScopeCluster:
	case model.ScopeNodeGroup:
		g, ok, err := s.findGroup(ctx, sc.Value)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, notFound("node group " + sc.Value + " not found")
		}
		nodes = g.Members
	case model.ScopeNode:
		nodes = []string{sc.Value}
	case model.ScopeNamespace, model.ScopeWorkload, model.ScopeImage, model.ScopeControlPlane:
		return nil, nil
	}
	agents, err := s.agentView(ctx)
	if err != nil {
		return nil, err
	}
	if nodes == nil {
		nodes = slices.Sorted(maps.Keys(agents.byNode))
	}
	type affected struct {
		nodes  []string
		detail string
	}
	byCode := map[string]*affected{}
	for _, n := range slices.Sorted(slices.Values(nodes)) {
		for _, g := range agents.of(n).Coverage {
			x := byCode[g.Code]
			if x == nil {
				x = &affected{detail: g.Detail}
				byCode[g.Code] = x
			}
			if !slices.Contains(x.nodes, n) {
				x.nodes = append(x.nodes, n)
			}
		}
	}
	out := make([]apigen.Gap, 0, len(byCode))
	for _, code := range slices.Sorted(maps.Keys(byCode)) {
		x := byCode[code]
		gap := apigen.Gap{Code: apigen.GapCode(code), Remedy: gapRemedy[apigen.GapCode(code)], What: fmt.Sprintf("%d nodes", len(x.nodes)),
			Detail: trimDetail(x.detail), Affects: apigen.GapAffects{Nodes: len(x.nodes)}}
		if len(x.nodes) == 1 {
			gap.What = x.nodes[0]
			t := scopeRef(model.Scope{Kind: model.ScopeNode, Value: x.nodes[0]}, x.nodes[0])
			gap.Target = &t
		}
		out = append(out, gap)
	}
	return out, nil
}

// trimDetail bounds a gap's detail to maxGapDetail characters.
func trimDetail(s string) string {
	if utf8.RuneCountInString(s) <= maxGapDetail {
		return s
	}
	return string([]rune(s)[:maxGapDetail])
}
