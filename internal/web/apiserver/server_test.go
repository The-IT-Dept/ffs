package apiserver_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/web/apigen"
	"github.com/the-it-dept/ffs/internal/web/apiserver"
	"github.com/the-it-dept/ffs/internal/web/webtest"
)

func TestServer_UnknownPathAndBadParameter(t *testing.T) {
	_, h := newAPI(t)
	for _, path := range []string{"/api/v1/nope", "/api/v1/feeds/"} {
		p := wantProblem(t, get(t, h, path), 404, apigen.ProblemCodeNotFound)
		require.NotNil(t, p.Instance)
		require.Equal(t, path, *p.Instance)
	}
	p := wantProblem(t, get(t, h, "/api/v1/findings?limit=abc"), 400, apigen.ProblemCodeInvalidParameter)
	require.NotNil(t, p.Detail)
	require.Contains(t, *p.Detail, "limit")
}

// V56: a request the client cancelled (the browser aborts superseded queries) is neither logged
// as an error nor answered 500; the handler just returns.
func TestServer_CancelledRequestIsNotAnError(t *testing.T) {
	f := webtest.Open(t)
	var (
		mu     sync.Mutex
		logged []string
	)
	o := f.Options()
	o.Log = funcr.New(func(prefix, args string) {
		mu.Lock()
		defer mu.Unlock()
		logged = append(logged, prefix+" "+args)
	}, funcr.Options{})
	h := apiserver.New(o).Handler()

	for _, target := range []string{"/api/v1/summary", "/api/v1/findings?facets=state,priority", "/api/v1/scope", "/api/v1/nodegroups"} {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		req := httptest.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		require.NotEqual(t, http.StatusInternalServerError, rec.Code, target)
		require.Empty(t, rec.Body.String(), target)
	}
	mu.Lock()
	defer mu.Unlock()
	require.Empty(t, logged)

	rec := get(t, h, "/api/v1/summary")
	require.Equal(t, http.StatusOK, rec.Code, "a live request is answered")
}
