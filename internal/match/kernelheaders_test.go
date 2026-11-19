package match

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

func TestKernelHeader(t *testing.T) {
	for _, tc := range []struct {
		p    model.Package
		want bool
	}{
		{model.Package{Ecosystem: "deb", Name: "linux-headers-6.1-amd64", SourceName: "linux"}, true},
		{model.Package{Ecosystem: "deb", Name: "linux-libc-dev", SourceName: "linux"}, true},
		{model.Package{Ecosystem: "deb", Name: "linux-kbuild-6.1", SourceName: "linux"}, true},
		{model.Package{Ecosystem: "rpm", Name: "kernel-headers", SourceName: "kernel"}, true},
		{model.Package{Ecosystem: "deb", Name: "linux-image-6.1", SourceName: "linux"}, false},
		{model.Package{Ecosystem: "rpm", Name: "linux-libc-dev", SourceName: "linux"}, false},          // wrong type
		{model.Package{Ecosystem: "deb", Name: "linux-libc-dev", SourceName: "linux-libc-dev"}, false}, // not from the kernel source
	} {
		require.Equal(t, tc.want, IsKernelHeader(tc.p), "%+v", tc.p)
	}
}
