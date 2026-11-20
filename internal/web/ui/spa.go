package ui

import (
	"bytes"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

// NotBuiltPage is served for every UI path when the binary was built without the web UI.
const NotBuiltPage = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>ffs</title></head><body><p>The ffs web UI is not part of this build. The read-only API is at /api/v1/.</p></body></html>`

const (
	htmlType      = "text/html; charset=utf-8"
	cacheNone     = "no-cache"
	cacheHashed   = "public, max-age=31536000, immutable"
	indexName     = "index.html"
	hashedAssetsP = "assets/"
)

// Handler serves the single-page application in dist:
//   - a regular file below /assets/ (hashed by the build) with a year-long immutable cache, and a
//     missing /assets/ file as a plain 404, so a stale hashed asset never receives HTML;
//   - any other regular file with no-cache;
//   - every other path, directories included, as index.html with no-cache, so client routes can be
//     opened directly;
//   - with no index.html in dist, every path as NotBuiltPage.
func Handler(dist fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		index, err := fs.ReadFile(dist, indexName)
		if err != nil {
			serveHTML(w, r, []byte(NotBuiltPage))
			return
		}
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name == "" || !fs.ValidPath(name) {
			serveHTML(w, r, index)
			return
		}
		info, err := fs.Stat(dist, name)
		regular := err == nil && info.Mode().IsRegular()
		switch {
		case regular && name != indexName:
			serveFile(w, r, dist, name, info)
		case regular:
			serveHTML(w, r, index)
		case strings.HasPrefix(name, hashedAssetsP):
			http.NotFound(w, r)
		default:
			serveHTML(w, r, index)
		}
	})
}

// serveFile serves one regular file. http.ServeContent sets Content-Type from the extension and
// answers HEAD and range requests.
func serveFile(w http.ResponseWriter, r *http.Request, dist fs.FS, name string, info fs.FileInfo) {
	data, err := fs.ReadFile(dist, name)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	cache := cacheNone
	if strings.HasPrefix(name, hashedAssetsP) {
		cache = cacheHashed
	}
	w.Header().Set("Cache-Control", cache)
	http.ServeContent(w, r, name, info.ModTime(), bytes.NewReader(data))
}

// serveHTML serves the index or NotBuiltPage. The Content-Type is set explicitly, because a host
// MIME database can drop the charset, and it never redirects (http.FileServer sends /index.html
// to /).
func serveHTML(w http.ResponseWriter, r *http.Request, body []byte) {
	w.Header().Set("Content-Type", htmlType)
	w.Header().Set("Cache-Control", cacheNone)
	http.ServeContent(w, r, indexName, time.Time{}, bytes.NewReader(body))
}
