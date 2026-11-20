// Package ui embeds the built web UI and serves it as a single-page application.
//
// The UI is built from ui/ into dist by `npm run build`. The build output is not committed: dist
// holds only .keep in a checkout, so `go build` works without a UI build and the server then
// answers every UI path with NotBuiltPage.
package ui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var embedded embed.FS

// Dist returns the embedded build output, rooted at dist.
func Dist() fs.FS {
	sub, err := fs.Sub(embedded, "dist")
	if err != nil {
		// fs.Sub fails only for an invalid directory name, and "dist" is a literal.
		panic(err)
	}
	return sub
}
