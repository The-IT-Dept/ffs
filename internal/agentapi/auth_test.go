package agentapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	authenticationv1 "k8s.io/api/authentication/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/the-it-dept/ffs/internal/agentapi/wire"
)

// reportRecorder is a ReportHandler that records its calls.
type reportRecorder struct {
	calls []wire.Report
	resp  wire.ReportResponse
	err   error
}

func (r *reportRecorder) Report(_ context.Context, _ Identity, rep *wire.Report) (wire.ReportResponse, error) {
	r.calls = append(r.calls, *rep)
	return r.resp, r.err
}

// sbomRecorder is an SBOMHandler that records its calls.
type sbomRecorder struct {
	calls []wire.SBOMResult
	err   error
}

func (r *sbomRecorder) SBOM(_ context.Context, _ Identity, res *wire.SBOMResult) error {
	r.calls = append(r.calls, *res)
	return r.err
}

func goodStatus() authenticationv1.TokenReviewStatus {
	return authenticationv1.TokenReviewStatus{Authenticated: true, Audiences: []string{"ffs-agent"},
		User: authenticationv1.UserInfo{Username: "system:serviceaccount:ffs-agent:ffs-agent",
			Extra: map[string]authenticationv1.ExtraValue{extraNodeName: {"worker-1"}, extraPodName: {"ffs-agent-x7k2p"}, extraPodUID: {"uid-1"}}}}
}

func TestAuth_RejectsWrongAudienceServiceAccountOrNode(t *testing.T) {
	ctx := context.Background()
	pods := fake.NewClientBuilder().WithObjects(agentPod("ffs-agent", "ffs-agent-x7k2p", "uid-1", "worker-2"),
		agentPod("default", "ffs-agent-elsewhere", "uid-3", "worker-3")).Build()
	authWith := func(st authenticationv1.TokenReviewStatus) (Authenticator, *[]authenticationv1.TokenReviewSpec) {
		c, specs := reviewer(t, func(authenticationv1.TokenReviewSpec) (authenticationv1.TokenReviewStatus, error) { return st, nil })
		return NewTokenReviewAuthenticator(c, pods, AuthOptions{Namespace: "ffs-agent", ServiceAccount: "ffs-agent"}), specs
	}

	a, specs := authWith(goodStatus())
	id, err := a.Authenticate(ctx, "bearer-token")
	require.NoError(t, err)
	require.Equal(t, Identity{Node: "worker-1", Pod: "ffs-agent-x7k2p", PodUID: "uid-1", ServiceAccount: "ffs-agent", Namespace: "ffs-agent"}, id)
	require.Equal(t, []authenticationv1.TokenReviewSpec{{Token: "bearer-token", Audiences: []string{"ffs-agent"}}}, *specs)

	podOnly := func(name, uid string) authenticationv1.TokenReviewStatus {
		st := goodStatus()
		st.User.Extra = map[string]authenticationv1.ExtraValue{extraPodName: {name}, extraPodUID: {uid}}
		return st
	}
	for name, mutate := range map[string]func(*authenticationv1.TokenReviewStatus){
		"not authenticated": func(st *authenticationv1.TokenReviewStatus) { st.Authenticated = false },
		"review error":      func(st *authenticationv1.TokenReviewStatus) { st.Error = "token has expired" },
		"API server audience": func(st *authenticationv1.TokenReviewStatus) {
			st.Audiences = []string{"https://kubernetes.default.svc"}
		},
		"no audience": func(st *authenticationv1.TokenReviewStatus) { st.Audiences = nil },
		"default SA": func(st *authenticationv1.TokenReviewStatus) {
			st.User.Username = "system:serviceaccount:ffs-agent:default"
		},
		"other namespace": func(st *authenticationv1.TokenReviewStatus) {
			st.User.Username = "system:serviceaccount:kube-system:ffs-agent"
		},
		"not a service account":  func(st *authenticationv1.TokenReviewStatus) { st.User.Username = "kubernetes-admin" },
		"no node and no pod":     func(st *authenticationv1.TokenReviewStatus) { st.User.Extra = nil },
		"pod UID mismatch":       func(st *authenticationv1.TokenReviewStatus) { *st = podOnly("ffs-agent-x7k2p", "uid-2") },
		"pod in other namespace": func(st *authenticationv1.TokenReviewStatus) { *st = podOnly("ffs-agent-elsewhere", "uid-3") },
	} {
		st := goodStatus()
		mutate(&st)
		a, _ := authWith(st)
		_, err := a.Authenticate(ctx, "bearer-token")
		require.ErrorIs(t, err, ErrUnauthenticated, name)
		require.NotContains(t, err.Error(), "bearer-token", "the token never appears in errors")
	}

	a, _ = authWith(podOnly("ffs-agent-x7k2p", "uid-1"))
	id, err = a.Authenticate(ctx, "bearer-token")
	require.NoError(t, err)
	require.Equal(t, "worker-2", id.Node, "without a node-name extra the node comes from the token's pod")

	a, specs = authWith(goodStatus())
	_, err = a.Authenticate(ctx, "")
	require.ErrorIs(t, err, ErrUnauthenticated)
	require.Empty(t, *specs, "an empty bearer is never reviewed")

	// Through the server: the token's node must be the report's node.
	a, _ = authWith(goodStatus())
	rec := &reportRecorder{}
	h := NewServer(ServerOptions{Auth: a, Reports: rec, MaxReportBytes: 1 << 20}).Handler()
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, wire.PathReport, strings.NewReader(`{"node":"worker-2","kind":"images"}`))
	req.Header.Set("Authorization", "Bearer bearer-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusForbidden, w.Code)
	body, err := io.ReadAll(w.Body)
	require.NoError(t, err)
	require.JSONEq(t, `{"error":"token is for node worker-1, not worker-2"}`, string(body))
	require.Empty(t, rec.calls)
}

func TestAuth_CachesBySHA256OfToken(t *testing.T) {
	ctx := context.Background()
	clk := newClock(t0)
	refuse := map[string]bool{"bad": true}
	c, specs := reviewer(t, func(spec authenticationv1.TokenReviewSpec) (authenticationv1.TokenReviewStatus, error) {
		if spec.Token == "down" {
			return authenticationv1.TokenReviewStatus{}, errors.New("connection refused")
		}
		if refuse[spec.Token] {
			return authenticationv1.TokenReviewStatus{Authenticated: false}, nil
		}
		return goodStatus(), nil
	})
	a := NewTokenReviewAuthenticator(c, fake.NewClientBuilder().Build(),
		AuthOptions{Namespace: "ffs-agent", ServiceAccount: "ffs-agent", Now: clk.Now})

	_, err := a.Authenticate(ctx, "tok-a")
	require.NoError(t, err)
	clk.Add(4*time.Minute + 59*time.Second)
	_, err = a.Authenticate(ctx, "tok-a")
	require.NoError(t, err)
	require.Len(t, *specs, 1, "a cached token is not reviewed again within 5m")
	clk.Add(2 * time.Second)
	_, err = a.Authenticate(ctx, "tok-a")
	require.NoError(t, err)
	require.Len(t, *specs, 2, "the cache entry expired")
	_, err = a.Authenticate(ctx, "tok-b")
	require.NoError(t, err)
	require.Len(t, *specs, 3)

	keys := func() []string {
		ta := a.(*tokenReviewAuth)
		ta.mu.Lock()
		defer ta.mu.Unlock()
		var out []string
		for k := range ta.cache {
			out = append(out, k)
		}
		slices.Sort(out)
		return out
	}
	hash := func(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }
	want := []string{hash("tok-a"), hash("tok-b")}
	slices.Sort(want)
	require.Equal(t, want, keys())
	for _, k := range keys() {
		require.NotContains(t, []string{"tok-a", "tok-b"}, k, "no raw token is stored")
	}

	for range 2 {
		_, err = a.Authenticate(ctx, "bad")
		require.ErrorIs(t, err, ErrUnauthenticated)
	}
	require.Len(t, *specs, 5, "a rejected token is never cached")

	_, err = a.Authenticate(ctx, "down")
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrUnauthenticated, "an unreachable API server is not a rejected token")
}

func TestAuth_CacheBounded(t *testing.T) {
	ctx := context.Background()
	clk := newClock(t0)
	c, _ := reviewer(t, func(authenticationv1.TokenReviewSpec) (authenticationv1.TokenReviewStatus, error) {
		return goodStatus(), nil
	})
	a := NewTokenReviewAuthenticator(c, fake.NewClientBuilder().Build(),
		AuthOptions{Namespace: "ffs-agent", ServiceAccount: "ffs-agent", Now: clk.Now}).(*tokenReviewAuth)
	for i := range maxAuthCache {
		_, err := a.Authenticate(ctx, "tok-"+string(rune(0x1000+i)))
		require.NoError(t, err)
	}
	require.Len(t, a.cache, maxAuthCache)
	_, err := a.Authenticate(ctx, "one more")
	require.NoError(t, err)
	require.Len(t, a.cache, 1, "a full cache with nothing expired is cleared")

	clk.Add(6 * time.Minute)
	_, err = a.Authenticate(ctx, "after expiry")
	require.NoError(t, err)
	require.Len(t, a.cache, 2, "expired entries stay until the cache is full")
}
