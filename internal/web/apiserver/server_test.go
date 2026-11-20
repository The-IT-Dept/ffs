package apiserver_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/web/apigen"
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
