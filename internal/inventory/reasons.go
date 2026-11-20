package inventory

import (
	"strings"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/registry"
)

// ReasonLayersDiscarded is the reason of an unresolvable image that no node agent can catalogue,
// because containerd kept only its manifest and config on the nodes that hold it.
const ReasonLayersDiscarded = "image layers were discarded by containerd on every node that holds the image"

// unresolvableFormats maps the reason formats of unresolvable images to their class, in the order
// they are tried. Side-loaded comes before not-found: the mismatch and not-found formats both end in
// " in the registry".
var unresolvableFormats = []struct {
	format string
	class  model.UnresolvableClass
}{
	{ReasonSideLoadedNoTag, model.UnresolvableSideLoaded},
	{ReasonSideLoadedMismatch, model.UnresolvableSideLoaded},
	{registry.ReasonUnauthorized, model.UnresolvableAuth},
	{ReasonUnreachable, model.UnresolvableUnreachable},
	{registry.ReasonNotFound, model.UnresolvableNotFound},
	{ReasonLayersDiscarded, model.UnresolvableLayersDiscarded},
}

// ClassifyUnresolvable returns the class of an unresolvable image's status reason: the first format
// it matches, else UnresolvableOther.
func ClassifyUnresolvable(reason string) model.UnresolvableClass {
	for _, f := range unresolvableFormats {
		if matchesFormat(reason, f.format) {
			return f.class
		}
	}
	return model.UnresolvableOther
}

// matchesFormat reports whether reason could have been produced by format. A format without verbs
// matches by equality; otherwise reason must start with the text before the first verb and end with
// the text after the last one (%s or %q), without the two overlapping.
func matchesFormat(reason, format string) bool {
	first := strings.IndexByte(format, '%')
	if first < 0 {
		return reason == format
	}
	last := max(strings.LastIndex(format, "%s"), strings.LastIndex(format, "%q"), first) // any verb is two characters
	prefix, suffix := format[:first], format[last+2:]
	return len(reason) >= len(prefix)+len(suffix) && strings.HasPrefix(reason, prefix) && strings.HasSuffix(reason, suffix)
}
