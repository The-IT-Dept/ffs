// Package version exposes build metadata for the ffs binary.
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// Version and Commit are set at build time with -ldflags -X.
var (
	Version = "dev"
	Commit  = ""
)

func commit() string {
	if Commit != "" {
		return Commit
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" && s.Value != "" {
				return s.Value
			}
		}
	}
	return "unknown"
}

// String returns the human-readable version line.
func String() string {
	return fmt.Sprintf("ffs %s (commit %s, %s, %s/%s)", Version, commit(), runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

// UserAgent is the User-Agent every outbound HTTP client must send.
func UserAgent() string {
	return fmt.Sprintf("ffs/%s (+https://github.com/The-IT-Dept/ffs)", Version)
}
