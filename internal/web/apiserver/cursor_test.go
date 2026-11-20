package apiserver

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
	"github.com/the-it-dept/ffs/internal/web/apigen"
)

func TestCursor_ForeignQueryIsInvalidCursorProblem(t *testing.T) {
	urgent := apigen.ListFindingsParams{Priority: &[]apigen.Priority{apigen.PriorityUrgent, apigen.PriorityHigh}}
	c := encodeCursor("listFindings", urgent, "store-key")
	require.NotNil(t, c)
	swapped := apigen.ListFindingsParams{Priority: &[]apigen.Priority{apigen.PriorityHigh, apigen.PriorityUrgent}, Cursor: c,
		Facets: &[]apigen.FindingFacet{apigen.FindingFacetPriority}}
	k, err := decodeCursor("listFindings", swapped, c) // value order, cursor and facets do not matter
	require.NoError(t, err)
	require.Equal(t, "store-key", k)

	for name, tc := range map[string]struct {
		op     string
		params any
		cursor string
	}{
		"other filter":           {"listFindings", apigen.ListFindingsParams{Priority: &[]apigen.Priority{apigen.PriorityLow}}, *c},
		"other operation":        {"listWorkloads", apigen.ListWorkloadsParams{}, *c},
		"garbage":                {"listFindings", urgent, "!!!"},
		"valid base64, not ours": {"listFindings", urgent, base64.RawURLEncoding.EncodeToString([]byte(`[1,2]`))},
	} {
		_, err = decodeCursor(tc.op, tc.params, &tc.cursor)
		var p *Problem
		require.ErrorAs(t, err, &p, name)
		require.Equal(t, 400, p.Status, name)
		require.Equal(t, apigen.ProblemCodeInvalidCursor, p.Code, name)
	}
	require.Equal(t, apigen.ProblemCodeInvalidCursor, problemOf(fmt.Errorf("page: %w", store.ErrBadCursor)).Code)
	require.Equal(t, apigen.ProblemCodeInvalidScope, problemOf(fmt.Errorf("%w: image", store.ErrScope)).Code)

	rec := httptest.NewRecorder()
	writeProblem(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/findings?cursor=x", nil), problemOf(err), "test",
		time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC))
	require.Equal(t, 400, rec.Code)
	require.Equal(t, "application/problem+json", rec.Header().Get("Content-Type"))
	var doc map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &doc))
	require.Equal(t, map[string]any{"cluster": "test", "generatedAt": "2026-11-19T00:00:00Z", "type": "about:blank",
		"title": "Bad Request", "status": float64(400), "instance": "/api/v1/findings", "code": "invalid_cursor"}, doc)

	require.Nil(t, encodeCursor("listFindings", urgent, ""))
}

func TestParams_ValidateAndCanonicalise(t *testing.T) {
	str := func(s string) *string { return &s }
	wantCode := func(err error, code apigen.ProblemCode) *Problem {
		t.Helper()
		var p *Problem
		require.ErrorAs(t, err, &p)
		require.Equal(t, http.StatusBadRequest, p.Status)
		require.Equal(t, code, p.Code)
		return p
	}

	sc, err := scopeParam(nil)
	require.NoError(t, err)
	require.Equal(t, model.Scope{Kind: model.ScopeCluster}, sc)
	sc, err = scopeParam(str("namespace:shop"))
	require.NoError(t, err)
	require.Equal(t, model.Scope{Kind: model.ScopeNamespace, Value: "shop"}, sc)
	_, err = scopeParam(str("namespace:"))
	require.Contains(t, wantCode(err, apigen.ProblemCodeInvalidScope).Detail, "scope: ")
	_, err = scopeParam(str("image:x"), model.ScopeCluster, model.ScopeNamespace)
	require.Contains(t, wantCode(err, apigen.ProblemCodeInvalidScope).Detail, "image")

	n, err := limitParam(nil)
	require.NoError(t, err)
	require.Equal(t, 50, n)
	for _, bad := range []int{0, 201} {
		_, err = limitParam(&bad)
		require.Contains(t, wantCode(err, apigen.ProblemCodeInvalidParameter).Detail, "limit: ")
	}
	n, err = limitParam(func() *int { v := 200; return &v }())
	require.NoError(t, err)
	require.Equal(t, 200, n)

	_, err = enumParam("priority", &[]apigen.Priority{"bogus"})
	p := wantCode(err, apigen.ProblemCodeInvalidParameter)
	require.Contains(t, p.Detail, "priority")
	require.Contains(t, p.Detail, "bogus")
	ps, err := enumParam("priority", &[]apigen.Priority{apigen.PriorityUrgent, apigen.PriorityHigh, apigen.PriorityUrgent})
	require.NoError(t, err)
	require.Equal(t, []apigen.Priority{apigen.PriorityHigh, apigen.PriorityUrgent}, ps)
	ps, err = enumParam[apigen.Priority]("priority", nil)
	require.NoError(t, err)
	require.Nil(t, ps)

	require.Equal(t, []string{"ops", "shop"}, stringsParam(&[]string{"shop", "", "ops", "shop"}))
	require.Nil(t, stringsParam(nil))
}
