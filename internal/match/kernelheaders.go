package match

import (
	"regexp"
	"sync"

	"github.com/the-it-dept/ffs/internal/model"
)

// KernelHeaderRule describes kernel-header packages. They carry the kernel's version but none of
// its code, so advisories reached through their upstream kernel source package are not theirs.
// Name and UpstreamName are anchored regular expressions; Type is the syft package type.
type KernelHeaderRule struct{ Name, UpstreamName, Type string }

// KernelHeaderRules are the grype CLI's kernel-header ignore rules (applied unless
// --match-upstream-kernel-headers), and the only definition of them in ffs.
var KernelHeaderRules = []KernelHeaderRule{
	{Name: "kernel-headers", UpstreamName: "kernel", Type: "rpm"},
	{Name: "linux(-.*)?-headers-.*", UpstreamName: "linux.*", Type: "deb"},
	{Name: "linux-libc-dev", UpstreamName: "linux", Type: "deb"},
	{Name: "linux-kbuild-.*", UpstreamName: "linux.*", Type: "deb"},
}

type kernelHeaderPattern struct {
	name, upstream *regexp.Regexp
	typ            string
}

var kernelHeaderPatterns = sync.OnceValue(func() []kernelHeaderPattern {
	out := make([]kernelHeaderPattern, len(KernelHeaderRules))
	for i, r := range KernelHeaderRules {
		out[i] = kernelHeaderPattern{
			name:     regexp.MustCompile(`^(?:` + r.Name + `)$`),
			upstream: regexp.MustCompile(`^(?:` + r.UpstreamName + `)$`),
			typ:      r.Type,
		}
	}
	return out
})

// IsKernelHeader reports whether p is a kernel-header package: its type, name and source package
// name match one of KernelHeaderRules.
func IsKernelHeader(p model.Package) bool {
	for _, r := range kernelHeaderPatterns() {
		if p.Ecosystem == r.typ && r.name.MatchString(p.Name) && r.upstream.MatchString(p.SourceName) {
			return true
		}
	}
	return false
}
