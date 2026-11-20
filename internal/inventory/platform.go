package inventory

import (
	"slices"
	"sort"

	corev1 "k8s.io/api/core/v1"

	"github.com/the-it-dept/ffs/internal/model"
)

// platformPins is what a pod spec's nodeSelector and required node affinity say about the platform of
// the nodes its pods may run on.
type platformPins struct {
	selector map[string]string         // kubernetes.io/arch and kubernetes.io/os, when set
	terms    []corev1.NodeSelectorTerm // required node affinity terms; nil when there is none
}

func pinsOf(spec *corev1.PodSpec) platformPins {
	p := platformPins{selector: spec.NodeSelector}
	if a := spec.Affinity; a != nil && a.NodeAffinity != nil && a.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution != nil {
		p.terms = a.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms
	}
	return p
}

// pinned reports whether the spec constrains the platform at all.
func (p platformPins) pinned() bool {
	if p.selector[corev1.LabelArchStable] != "" || p.selector[corev1.LabelOSStable] != "" {
		return true
	}
	for _, t := range p.terms {
		for _, e := range t.MatchExpressions {
			if slices.Contains(platformLabels, e.Key) {
				return true
			}
		}
	}
	return false
}

// allows reports whether a node of platform np satisfies the pins: the nodeSelector, and one of the
// affinity terms (they are ORed; a term's expressions are ANDed). Only expressions on the platform
// labels are evaluated; Exists, Gt and Lt do not constrain the platform.
func (p platformPins) allows(np NodePlatform) bool {
	label := func(key string) string {
		if key == corev1.LabelArchStable {
			return np.Arch
		}
		return np.OS
	}
	for _, k := range platformLabels {
		if v, ok := p.selector[k]; ok && v != label(k) {
			return false
		}
	}
	if len(p.terms) == 0 {
		return true
	}
	return slices.ContainsFunc(p.terms, func(t corev1.NodeSelectorTerm) bool {
		for _, e := range t.MatchExpressions {
			if !slices.Contains(platformLabels, e.Key) {
				continue
			}
			v := label(e.Key)
			switch e.Operator {
			case corev1.NodeSelectorOpIn:
				if !slices.Contains(e.Values, v) {
					return false
				}
			case corev1.NodeSelectorOpNotIn:
				if slices.Contains(e.Values, v) {
					return false
				}
			case corev1.NodeSelectorOpDoesNotExist:
				return false
			}
		}
		return true
	})
}

// named returns the platforms the pins name outright, in order: for each of arch and OS, the
// nodeSelector's value, else the values of the affinity terms' In expressions, else def's.
func (p platformPins) named(def NodePlatform) []NodePlatform {
	values := func(key, fallback string) []string {
		if v := p.selector[key]; v != "" {
			return []string{v}
		}
		var out []string
		for _, t := range p.terms {
			for _, e := range t.MatchExpressions {
				if e.Key == key && e.Operator == corev1.NodeSelectorOpIn {
					out = append(out, e.Values...)
				}
			}
		}
		if len(out) == 0 {
			return []string{fallback}
		}
		return out
	}
	var out []NodePlatform
	for _, a := range values(corev1.LabelArchStable, def.Arch) {
		for _, o := range values(corev1.LabelOSStable, def.OS) {
			if np := (NodePlatform{OS: o, Arch: a}); !slices.Contains(out, np) {
				out = append(out, np)
			}
		}
	}
	return out
}

// templatePlatform is the platform an owner with no running pods is resolved at. When its template
// pins kubernetes.io/arch or kubernetes.io/os (nodeSelector or required node affinity) to platforms
// other than the majority one, it is the platform of the most Ready nodes the pins allow, or, with
// none, the first platform the pins name; otherwise it is majority, the majority Ready-node platform.
func templatePlatform(spec *corev1.PodSpec, nodes []model.Node, majority NodePlatform) NodePlatform {
	pins := pinsOf(spec)
	if !pins.pinned() || pins.allows(majority) {
		return majority
	}
	counts := map[NodePlatform]int{}
	for _, n := range nodes {
		if np := (NodePlatform{OS: n.OS, Arch: n.Arch}); n.Ready && n.OS != "" && n.Arch != "" && pins.allows(np) {
			counts[np]++
		}
	}
	if len(counts) > 0 {
		platforms := make([]NodePlatform, 0, len(counts))
		for np := range counts {
			platforms = append(platforms, np)
		}
		sort.Slice(platforms, func(i, j int) bool {
			if counts[platforms[i]] != counts[platforms[j]] {
				return counts[platforms[i]] > counts[platforms[j]]
			}
			return platforms[i].Key() < platforms[j].Key()
		})
		return platforms[0]
	}
	for _, np := range pins.named(majority) {
		if pins.allows(np) {
			return np
		}
	}
	return majority
}
