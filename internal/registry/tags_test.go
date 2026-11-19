package registry

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/registry/regtest"
)

// tagQueries records the query of every tags/list request; with dropLast it also strips last=, like
// a registry that ignores it.
type tagQueries struct {
	mu       sync.Mutex
	got      []url.Values
	dropLast bool
}

func (q *tagQueries) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/tags/list") {
			v := r.URL.Query()
			q.mu.Lock()
			q.got = append(q.got, v)
			q.mu.Unlock()
			if q.dropLast {
				v.Del("last")
				r.URL.RawQuery = v.Encode()
			}
		}
		next.ServeHTTP(w, r)
	})
}

func TestListTags_LastFallback(t *testing.T) {
	q := &tagQueries{}
	s := regtest.Start(t, regtest.WithMiddleware(q.middleware))
	img := randomImage(t)
	for _, tag := range []string{"1.0", "1.1", "1.2", "1.3", "1.4"} {
		s.Push(t, "app:"+tag, img)
	}
	c := New(Options{})
	c.pageSize = 2

	tags, err := c.ListTags(ctx, s.Host+"/app", CredSet{})
	require.NoError(t, err)
	require.Equal(t, []string{"1.0", "1.1", "1.2", "1.3", "1.4"}, tags)
	require.Len(t, q.got, 3)
	for i, last := range []string{"", "1.1", "1.3"} {
		require.Equal(t, "2", q.got[i].Get("n"))
		require.Equal(t, last, q.got[i].Get("last"))
	}

	ignoring := &tagQueries{dropLast: true}
	s2 := regtest.Start(t, regtest.WithMiddleware(ignoring.middleware))
	for _, tag := range []string{"1.0", "1.1", "1.2"} {
		s2.Push(t, "app:"+tag, img)
	}
	tags, err = c.ListTags(ctx, s2.Host+"/app", CredSet{})
	require.NoError(t, err)
	require.Equal(t, []string{"1.0", "1.1"}, tags)
	require.Len(t, ignoring.got, 2)
}

// linkRegistry serves tags/list for repo "r" in pages chained by Link headers keyed on last=.
func linkRegistry(t *testing.T, pages map[string][]string, links map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/":
			w.WriteHeader(http.StatusOK)
		case "/v2/r/tags/list":
			last := r.URL.Query().Get("last")
			if l := links[last]; l != "" {
				w.Header().Set("Link", l)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"name": "r", "tags": pages[last]})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestListTags_LinkHeader(t *testing.T) {
	pages := map[string][]string{"": {"a", "b"}, "b": {"c", "d"}, "d": {"e"}}
	srv := linkRegistry(t, pages, map[string]string{
		"":  `</v2/r/tags/list?n=2&last=b>; rel="next"`,
		"b": `</v2/r/tags/list?n=2&last=d>; rel="next"`,
	})
	c := New(Options{})
	tags, err := c.ListTags(ctx, strings.TrimPrefix(srv.URL, "http://")+"/r", CredSet{})
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b", "c", "d", "e"}, tags)

	// A next link to another host is not followed.
	off := linkRegistry(t, pages, map[string]string{"": `<http://elsewhere.invalid/v2/r/tags/list?n=2&last=b>; rel="next"`})
	tags, err = c.ListTags(ctx, strings.TrimPrefix(off.URL, "http://")+"/r", CredSet{})
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b"}, tags)
}

func TestIsArtifactTag(t *testing.T) {
	h := strings.Repeat("ab", 32)
	for _, tag := range []string{"sha256-" + h, "sha256-" + h + ".sig", "sha256-" + h + ".att", "sha256-" + h + ".sbom",
		"1.25.3-metadata", "rc-3f2a1b9", "main-3f2a1b9", "1.2.3-3f2a1b9c"} {
		require.True(t, IsArtifactTag(tag), tag)
	}
	for _, tag := range []string{"1.2.3-3f2a1b9c0", "1.0-20240115", "sha256-abc", "metadata", "1.27.3", "1.27-alpine", "latest", "bookworm"} {
		require.False(t, IsArtifactTag(tag), tag)
	}
}
