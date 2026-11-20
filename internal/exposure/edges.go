package exposure

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/the-it-dept/ffs/internal/model"
)

func hostNetworkEdge() model.ExposureEdge {
	return model.ExposureEdge{Entry: model.EntryHostNetwork, Path: "hostNetwork"}
}

func hostPortEdge(port int32, proto corev1.Protocol) model.ExposureEdge {
	listener := fmt.Sprintf("%d/%s", port, proto)
	return model.ExposureEdge{Entry: model.EntryHostPort, Listener: listener, Path: "hostPort " + listener}
}

// serviceEdge is the edge of a Service that is itself the entry point; ref is its "ns/name".
func serviceEdge(entry model.EntryKind, ref, path string) model.ExposureEdge {
	return model.ExposureEdge{Entry: entry, EntryName: ref, Service: ref, Path: path}
}

// withPath sets e's Path to path, unless e is internal: an internal entry point yields no path.
func withPath(e model.ExposureEdge, path string) model.ExposureEdge {
	if !e.Internal {
		e.Path = path
	}
	return e
}

// serviceRef is "ns/name:port", or "ns/name" when port is "".
func serviceRef(ns, name, port string) string {
	if port == "" {
		return ns + "/" + name
	}
	return ns + "/" + name + ":" + port
}

// sortEdges returns es sorted by Entry, EntryName, Listener, Hostname, Route, Service, Internal and
// Path, with duplicates dropped; nil when es is empty.
func sortEdges(es []model.ExposureEdge) []model.ExposureEdge {
	if len(es) == 0 {
		return nil
	}
	out := slices.Clone(es)
	slices.SortFunc(out, func(a, b model.ExposureEdge) int {
		return cmp.Or(strings.Compare(string(a.Entry), string(b.Entry)), strings.Compare(a.EntryName, b.EntryName),
			strings.Compare(a.Listener, b.Listener), strings.Compare(a.Hostname, b.Hostname), strings.Compare(a.Route, b.Route),
			strings.Compare(a.Service, b.Service), cmp.Compare(boolRank(a.Internal), boolRank(b.Internal)),
			strings.Compare(a.Path, b.Path))
	})
	return slices.Compact(out)
}

func boolRank(b bool) int {
	if b {
		return 1
	}
	return 0
}

// pathsOf returns the sorted, de-duplicated non-empty paths of es; nil when there are none.
func pathsOf(es []model.ExposureEdge) []string {
	var out []string
	for _, e := range es {
		if e.Path != "" {
			out = append(out, e.Path)
		}
	}
	if len(out) == 0 {
		return nil
	}
	slices.Sort(out)
	return slices.Compact(out)
}
