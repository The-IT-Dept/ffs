package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
	"github.com/the-it-dept/ffs/internal/web/webtest"
)

// seededOwner is the workload POST /transition adds a finding to.
const seededOwner = "Deployment/shop/web"

// recomputer is told which owners' findings changed; *live.Hub implements it.
type recomputer interface {
	OwnersRecomputed(ctx context.Context, keys []string)
}

// transitionResult is the body of a POST /transition answer.
type transitionResult struct {
	Advisory    string `json:"advisory"`
	Fingerprint string `json:"fingerprint"`
	Owner       string `json:"owner"`
}

// errNoTemplate means the fixture holds no finding of seededOwner to copy; the control answers it
// with 404 and noTemplate.
var errNoTemplate = errors.New("no finding of " + seededOwner + " to copy")

const noTemplate = seededOwner + " has no findings in this fixture"

// control is the listener the browser tests use to change the store while a page is open.
type control struct {
	st      *store.Store
	cluster string
	hub     recomputer

	mu sync.Mutex
	n  int // advisories added so far
}

func newControl(st *store.Store, cluster string, hub recomputer) *control {
	return &control{st: st, cluster: cluster, hub: hub}
}

// ServeHTTP answers POST /transition by adding one urgent finding to seededOwner; any other method
// on that path is 405 and any other path 404.
func (c *control) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/transition" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	f, err := c.addUrgent(r.Context())
	switch {
	case errors.Is(err, errNoTemplate):
		http.Error(w, noTemplate, http.StatusNotFound)
		return
	case err != nil:
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(transitionResult{Advisory: f.AdvisoryID, Fingerprint: f.Fingerprint, Owner: f.Owner.Key()})
}

// addUrgent copies a finding of seededOwner into a new open urgent finding on a new advisory,
// CVE-2099-<n>, writes it with its NewAdvisory transition, and tells the hub the owner changed.
func (c *control) addUrgent(ctx context.Context) (model.Finding, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fs, err := c.st.FindingsForOwner(ctx, seededOwner)
	if err != nil {
		return model.Finding{}, err
	}
	if len(fs) == 0 {
		return model.Finding{}, errNoTemplate
	}
	f := fs[0]
	if i := slices.IndexFunc(fs, func(x model.Finding) bool { return x.State == model.StateOpen }); i >= 0 {
		f = fs[i]
	}

	c.n++
	id := fmt.Sprintf("CVE-2099-%04d", c.n)
	at := webtest.Now.Add(time.Duration(c.n) * time.Minute)
	f.AdvisoryID = id
	f.Fingerprint = model.FindingFingerprint(c.cluster, f.Owner, f.ImageRepo, id)
	f.Severity, f.Priority, f.State = model.SeverityCritical, model.PriorityUrgent, model.StateOpen
	f.ExceptedBy, f.ResolvedAt, f.Suggestion, f.Provisional = "", nil, nil, false
	f.Observed, f.Matched, f.LastSeen = at, at, at

	if err := c.st.UpsertAdvisory(ctx, model.Advisory{ID: id, Title: "Seeded advisory for live update checks", Published: at,
		Observed: at}); err != nil {
		return model.Finding{}, err
	}
	if err := c.st.ApplyFindings(ctx, []model.Finding{f}, []model.Transition{{Fingerprint: f.Fingerprint, Owner: f.Owner,
		AdvisoryID: id, ToState: model.StateOpen, FromPriority: model.PriorityNone, ToPriority: model.PriorityUrgent,
		Trigger: model.TriggerNewAdvisory, At: at}}); err != nil {
		return model.Finding{}, err
	}
	c.hub.OwnersRecomputed(ctx, []string{seededOwner})
	return f, nil
}
