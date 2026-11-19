package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/the-it-dept/ffs/internal/model"
)

type handler struct{ svc *Service }

// NewHandler serves the read-only API below /api/v1/. Anything but GET and HEAD is a 405.
func NewHandler(svc *Service) http.Handler {
	h := &handler{svc: svc}
	mux := http.NewServeMux()
	for pattern, fn := range map[string]http.HandlerFunc{
		"/findings":                         h.findings,
		"/findings/{id}":                    h.finding,
		"/vulnerabilities":                  h.vulnerabilities,
		"/vulnerabilities/{id}":             h.vulnerability,
		"/owners":                           h.owners,
		"/owners/{kind}/{namespace}/{name}": h.owner,
		"/images":                           h.images,
		"/images/{digest}":                  h.image,
		"/nodes":                            h.nodes,
		"/nodes/{name}":                     h.node,
		"/cluster":                          h.cluster,
		"/suggestions":                      h.suggestions,
		"/exceptions":                       h.exceptions,
		"/feeds":                            h.feeds,
		"/search":                           h.search,
	} {
		mux.HandleFunc("GET /api/v1"+pattern, fn)
	}
	mux.HandleFunc("/api/v1/", func(w http.ResponseWriter, _ *http.Request) { h.fail(w, http.StatusNotFound, "not found") })
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			h.fail(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (h *handler) write(w http.ResponseWriter, status int, v any) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		h.svc.o.Log.Error(err, "encode API response")
		status, buf = http.StatusInternalServerError, *bytes.NewBufferString(`{"error":"internal error"}` + "\n")
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func (h *handler) fail(w http.ResponseWriter, status int, msg string) {
	h.write(w, status, struct {
		Cluster string `json:"cluster"`
		Error   string `json:"error"`
	}{h.svc.ClusterName(), msg})
}

// internal logs err and answers 500 without its text.
func (h *handler) internal(w http.ResponseWriter, r *http.Request, err error) {
	h.svc.o.Log.Error(err, "API request failed", "path", r.URL.Path)
	h.fail(w, http.StatusInternalServerError, "internal error")
}

func (h *handler) item(w http.ResponseWriter, v any) {
	h.write(w, http.StatusOK, struct {
		Cluster string `json:"cluster"`
		Item    any    `json:"item"`
	}{h.svc.ClusterName(), v})
}

// list writes an unpaged list: Total is its length.
func list[T any](h *handler, w http.ResponseWriter, items []T) {
	h.write(w, http.StatusOK, Page[T]{Cluster: h.svc.ClusterName(), Items: nz(items), Total: len(items)})
}

// one answers a single-object lookup: 200 with the item, 404 when absent, 500 on error.
func one[T any](h *handler, w http.ResponseWriter, r *http.Request, v T, ok bool, err error, what string) {
	switch {
	case err != nil:
		h.internal(w, r, err)
	case !ok:
		h.fail(w, http.StatusNotFound, what+" not found")
	default:
		h.item(w, v)
	}
}

func (h *handler) findings(w http.ResponseWriter, r *http.Request) {
	q, err := parseFindingQuery(r)
	if err != nil {
		h.fail(w, http.StatusBadRequest, err.Error())
		return
	}
	page, err := h.svc.Findings(r.Context(), q)
	if err != nil {
		h.internal(w, r, err)
		return
	}
	h.write(w, http.StatusOK, page)
}

func parseFindingQuery(r *http.Request) (FindingQuery, error) {
	v := r.URL.Query()
	q := FindingQuery{Namespace: v.Get("namespace"), Owner: v.Get("owner"), Advisory: v.Get("advisory"),
		States: []model.FindingState{model.StateOpen}}
	if p := v.Get("priority"); p != "" {
		pr, err := model.ParsePriority(p)
		if err != nil {
			return q, err
		}
		q.MinPriority = pr
	}
	if st := v.Get("state"); st != "" {
		states, err := parseStates(st)
		if err != nil {
			return q, err
		}
		q.States = states
	}
	var err error
	if q.Limit, err = intParam(v.Get("limit"), "limit"); err != nil {
		return q, err
	}
	if q.Offset, err = intParam(v.Get("offset"), "offset"); err != nil {
		return q, err
	}
	return q, nil
}

// parseStates parses a comma-separated state list; "all" anywhere in it means no state filter (nil).
func parseStates(s string) ([]model.FindingState, error) {
	var out []model.FindingState
	for _, part := range strings.Split(s, ",") {
		switch st := model.FindingState(strings.TrimSpace(part)); st {
		case model.StateOpen, model.StateExcepted, model.StateResolved:
			out = append(out, st)
		case "all":
			return nil, nil
		default:
			return nil, fmt.Errorf("invalid state %q: want open, excepted, resolved or all", part)
		}
	}
	return out, nil
}

// intParam parses an optional non-negative integer; absent is 0.
func intParam(s, name string) (int, error) {
	if s == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid %s %q: want a non-negative integer", name, s)
	}
	return n, nil
}

func (h *handler) finding(w http.ResponseWriter, r *http.Request) {
	v, ok, err := h.svc.Finding(r.Context(), r.PathValue("id"))
	one(h, w, r, v, ok, err, "finding")
}

func (h *handler) vulnerabilities(w http.ResponseWriter, r *http.Request) {
	v, err := h.svc.Vulnerabilities(r.Context())
	if err != nil {
		h.internal(w, r, err)
		return
	}
	list(h, w, v)
}

func (h *handler) vulnerability(w http.ResponseWriter, r *http.Request) {
	v, ok, err := h.svc.Vulnerability(r.Context(), r.PathValue("id"))
	one(h, w, r, v, ok, err, "vulnerability")
}

func (h *handler) owners(w http.ResponseWriter, r *http.Request) {
	v, err := h.svc.Owners(r.Context())
	if err != nil {
		h.internal(w, r, err)
		return
	}
	list(h, w, v)
}

func (h *handler) owner(w http.ResponseWriter, r *http.Request) {
	ref := ParseOwnerPath(r.PathValue("kind"), r.PathValue("namespace"), r.PathValue("name"))
	v, ok, err := h.svc.Owner(r.Context(), ref)
	one(h, w, r, v, ok, err, "owner")
}

func (h *handler) images(w http.ResponseWriter, r *http.Request) {
	v, err := h.svc.Images(r.Context())
	if err != nil {
		h.internal(w, r, err)
		return
	}
	list(h, w, v)
}

func (h *handler) image(w http.ResponseWriter, r *http.Request) {
	v, ok, err := h.svc.Image(r.Context(), r.PathValue("digest"))
	one(h, w, r, v, ok, err, "image")
}

func (h *handler) nodes(w http.ResponseWriter, r *http.Request) {
	v, err := h.svc.Nodes(r.Context())
	if err != nil {
		h.internal(w, r, err)
		return
	}
	list(h, w, v)
}

func (h *handler) node(w http.ResponseWriter, r *http.Request) {
	v, ok, err := h.svc.Node(r.Context(), r.PathValue("name"))
	one(h, w, r, v, ok, err, "node")
}

func (h *handler) cluster(w http.ResponseWriter, r *http.Request) {
	v, err := h.svc.Cluster(r.Context())
	one(h, w, r, v, err == nil, err, "cluster")
}

func (h *handler) suggestions(w http.ResponseWriter, r *http.Request) {
	v, err := h.svc.Suggestions(r.Context())
	if err != nil {
		h.internal(w, r, err)
		return
	}
	list(h, w, v)
}

func (h *handler) exceptions(w http.ResponseWriter, r *http.Request) {
	v, err := h.svc.Exceptions(r.Context())
	if err != nil {
		h.internal(w, r, err)
		return
	}
	list(h, w, v)
}

func (h *handler) feeds(w http.ResponseWriter, r *http.Request) {
	v, err := h.svc.Feeds(r.Context())
	if err != nil {
		h.internal(w, r, err)
		return
	}
	h.write(w, http.StatusOK, struct {
		Page[FeedView]
		Attribution []Source `json:"attribution"`
	}{Page[FeedView]{Cluster: h.svc.ClusterName(), Items: v, Total: len(v)}, Sources})
}

func (h *handler) search(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		h.fail(w, http.StatusBadRequest, "q is required")
		return
	}
	v, err := h.svc.Search(r.Context(), q, strings.TrimSpace(r.URL.Query().Get("lt")))
	one(h, w, r, v, err == nil, err, "search")
}
