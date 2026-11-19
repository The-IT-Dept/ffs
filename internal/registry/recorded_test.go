package registry

import (
	"bufio"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// recorded is a raw HTTP response captured from a real registry (testdata/*.txt).
type recorded struct {
	status int
	header http.Header
	body   []byte
}

func loadRecorded(t *testing.T, file string) recorded {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", file)) //nolint:gosec // fixed fixture names under testdata
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	resp, err := http.ReadResponse(bufio.NewReader(f), nil)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return recorded{status: resp.StatusCode, header: resp.Header, body: body}
}

// replay writes the recorded response, passing every header value through rewrite.
func (r recorded) replay(w http.ResponseWriter, rewrite func(string) string) {
	for k, vs := range r.header {
		if k == "Connection" {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, rewrite(v))
		}
	}
	w.WriteHeader(r.status)
	_, _ = w.Write(r.body)
}

func unchanged(v string) string { return v }

func TestBudget_RecordedDockerHubHeaders(t *testing.T) {
	rec := loadRecorded(t, "dockerhub-manifest-get.txt")
	digest := rec.header.Get("Docker-Content-Digest")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/":
			w.WriteHeader(http.StatusOK)
		case "/v2/library/nginx/manifests/" + digest:
			rec.replay(w, unchanged)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")

	c := New(Options{Now: newClock().Now})
	_, err := c.Image(ctx, host+"/library/nginx", digest, CredSet{})
	require.NoError(t, err)
	require.Equal(t, []BudgetState{{Registry: host, Known: true, Limit: 100, Remaining: 76, Window: 6 * time.Hour}}, c.Budgets())
}

func TestKeychain_GHCRTokenChallenge(t *testing.T) {
	challenge := loadRecorded(t, "ghcr-token-challenge.txt")
	const token = "replayed-token"
	digest := "sha256:" + strings.Repeat("0f", 32)
	var (
		mu     sync.Mutex
		tokens []url.Values
		host   string
	)
	toReplay := func(v string) string { return strings.ReplaceAll(v, "https://ghcr.io/token", "http://"+host+"/token") }
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/":
			challenge.replay(w, toReplay)
		case "/token":
			mu.Lock()
			if r.Method == http.MethodGet {
				tokens = append(tokens, r.URL.Query())
			}
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"token":"`+token+`"}`)
		case "/v2/x/y/manifests/1.0":
			if r.Header.Get("Authorization") != "Bearer "+token {
				challenge.replay(w, toReplay)
				return
			}
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			w.Header().Set("Content-Length", "512")
			w.Header().Set("Docker-Content-Digest", digest)
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	host = srv.Listener.Addr().String()
	srv.Start()
	t.Cleanup(srv.Close)

	c := New(Options{})
	d, err := c.ResolveTag(ctx, host+"/x/y", "1.0", CredSet{})
	require.NoError(t, err)
	require.Equal(t, digest, d)
	mu.Lock()
	defer mu.Unlock()
	require.Len(t, tokens, 1)
	require.Equal(t, "repository:x/y:pull", tokens[0].Get("scope"))
	require.Equal(t, "ghcr.io", tokens[0].Get("service"))
}
