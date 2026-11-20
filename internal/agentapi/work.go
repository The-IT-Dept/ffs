package agentapi

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/go-logr/logr"

	"github.com/the-it-dept/ffs/internal/agentapi/wire"
	"github.com/the-it-dept/ffs/internal/inventory"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/sbom"
	"github.com/the-it-dept/ffs/internal/store"
)

const (
	defaultWorkQuarantineAfter = 2
	defaultWorkQuarantineFor   = 24 * time.Hour
)

// offeredClasses are the unresolvable images a node agent may catalogue from its content store.
var offeredClasses = []model.UnresolvableClass{
	model.UnresolvableSideLoaded, model.UnresolvableAuth, model.UnresolvableUnreachable, model.UnresolvableNotFound,
}

// WorkOptions configures a WorkQueue.
type WorkOptions struct {
	Store           *store.Store
	Acquirer        AgentIngest
	Pods            PodIndex
	PerReport       int           // images offered per report at most; 0 offers none
	Timeout         time.Duration // how long an offer is held for its node
	QuarantineAfter int           // counted failures that quarantine an image; 0: 2
	QuarantineFor   time.Duration // 0: 24h
	Now             func() time.Time
	Log             logr.Logger
}

// WorkQueue offers unresolvable images to the node agents that hold them and accepts the SBOMs they send
// back. Offers live in memory only: after a restart every image is offered afresh.
type WorkQueue struct {
	o WorkOptions

	mu       sync.Mutex
	offers   map[string]offer     // digest → its live offer
	seen     map[string]time.Time // digest → when Offer first saw it as offerable work, for oldest-first order
	declined map[string]time.Time // node+"\x00"+digest → when the node may be offered the digest again
}

type offer struct {
	id, node string
	deadline time.Time
}

var (
	_ Offerer     = (*WorkQueue)(nil)
	_ SBOMHandler = (*WorkQueue)(nil)
)

// NewWorkQueue returns a WorkQueue.
func NewWorkQueue(o WorkOptions) *WorkQueue {
	if o.QuarantineAfter == 0 {
		o.QuarantineAfter = defaultWorkQuarantineAfter
	}
	if o.QuarantineFor == 0 {
		o.QuarantineFor = defaultWorkQuarantineFor
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &WorkQueue{o: o, offers: map[string]offer{}, seen: map[string]time.Time{}, declined: map[string]time.Time{}}
}

func declineKey(node, digest string) string { return node + "\x00" + digest }

// Offer picks up to PerReport images for node's agent to catalogue, oldest first: unresolvable images of an
// offered class that a pod on node runs, that node holds complete, that are not offered to any node or
// declined by this one, and that are not quarantined.
func (q *WorkQueue) Offer(ctx context.Context, node string) ([]wire.WorkRequest, error) {
	if q.o.PerReport <= 0 {
		return nil, nil
	}
	now := q.o.Now()
	imgs, err := q.o.Store.ListImages(ctx, store.ImageFilter{Statuses: []model.ImageStatus{model.ImageUnresolvable}})
	if err != nil {
		return nil, err
	}
	offerable := make(map[string]bool, len(imgs))
	candidates := imgs[:0]
	for _, img := range imgs {
		if slices.Contains(offeredClasses, inventory.ClassifyUnresolvable(img.StatusReason)) {
			offerable[img.Digest] = true
			candidates = append(candidates, img)
		}
	}
	q.forget(now, offerable)
	if len(candidates) == 0 {
		return nil, nil
	}

	pods, err := q.o.Pods.DigestsOnNode(ctx, node)
	if err != nil {
		return nil, err
	}
	candidates = slices.DeleteFunc(candidates, func(img model.Image) bool {
		return !pods[img.Digest] && (img.IndexDigest == "" || !pods[img.IndexDigest])
	})
	if len(candidates) == 0 {
		return nil, nil
	}
	held, err := q.o.Store.NodeImages(ctx, node)
	if err != nil {
		return nil, err
	}
	candidates = slices.DeleteFunc(candidates, func(img model.Image) bool {
		return !heldComplete(held, img.Digest, img.IndexDigest)
	})
	if len(candidates) == 0 {
		return nil, nil
	}

	q.mu.Lock()
	defer q.mu.Unlock()
	slices.SortFunc(candidates, func(a, b model.Image) int {
		return cmp.Or(q.seen[a.Digest].Compare(q.seen[b.Digest]), cmp.Compare(a.Digest, b.Digest))
	})
	var work []wire.WorkRequest
	for _, img := range candidates {
		if len(work) == q.o.PerReport {
			break
		}
		if o, ok := q.offers[img.Digest]; ok && o.deadline.After(now) {
			continue
		}
		if until, ok := q.declined[declineKey(node, img.Digest)]; ok && until.After(now) {
			continue
		}
		job, ok, err := q.o.Store.AgentJobOf(ctx, img.Digest)
		if err != nil {
			return nil, err
		}
		if ok && job.QuarantinedUntil.After(now) {
			continue
		}
		id, err := offerID()
		if err != nil {
			return nil, err
		}
		w := wire.WorkRequest{ID: id, Digest: img.Digest, Platform: img.Platform, Deadline: now.Add(q.o.Timeout)}
		q.offers[img.Digest] = offer{id: id, node: node, deadline: w.Deadline}
		work = append(work, w)
	}
	return work, nil
}

// forget records when each offerable digest was first seen, and drops what is no longer needed: the order of
// digests that are no longer offerable, expired offers and expired declines.
func (q *WorkQueue) forget(now time.Time, offerable map[string]bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for d := range offerable {
		if _, ok := q.seen[d]; !ok {
			q.seen[d] = now
		}
	}
	for d := range q.seen {
		if !offerable[d] {
			delete(q.seen, d)
		}
	}
	for d, o := range q.offers {
		if !o.deadline.After(now) {
			delete(q.offers, d)
		}
	}
	for k, until := range q.declined {
		if !until.After(now) {
			delete(q.declined, k)
		}
	}
}

func offerID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("offer ID: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// heldComplete reports whether a node holding rows holds image d complete: a complete row for d itself, for
// the manifest whose config digest is d (a bare config digest), or for d's index.
func heldComplete(rows []model.NodeImage, d, indexDigest string) bool {
	for _, r := range rows {
		if r.Complete && (r.Digest == d || r.ConfigDigest == d || (indexDigest != "" && r.Digest == indexDigest)) {
			return true
		}
	}
	return false
}

// SBOM applies a node agent's result for one image. It is accepted only from a node a pod of which runs the
// image (or its index), whether or not the image was offered to it; anything else is ErrForbidden with
// nothing written.
func (q *WorkQueue) SBOM(ctx context.Context, id Identity, res *wire.SBOMResult) error {
	if res.Node != id.Node {
		return fmt.Errorf("%w: result is for node %s, not %s", ErrForbidden, res.Node, id.Node)
	}
	img, ok, err := q.o.Store.GetImage(ctx, res.Digest)
	if err != nil {
		return err
	}
	pods, err := q.o.Pods.DigestsOnNode(ctx, id.Node)
	if err != nil {
		return err
	}
	if !pods[res.Digest] && (!ok || img.IndexDigest == "" || !pods[img.IndexDigest]) {
		return fmt.Errorf("%w: no pod on %s runs %s", ErrForbidden, id.Node, res.Digest)
	}
	hasSyft := len(bytes.TrimSpace(res.SyftJSON)) > 0 && !bytes.Equal(bytes.TrimSpace(res.SyftJSON), []byte("null"))
	set := 0
	for _, b := range []bool{hasSyft, res.Unavailable != "", res.Failure != ""} {
		if b {
			set++
		}
	}
	if set != 1 {
		return fmt.Errorf("%w: a result carries exactly one of syftJSON, unavailable and failure", ErrBadRequest)
	}
	switch res.Unavailable {
	case "", wire.UnavailableNotFound, wire.UnavailableLayersDiscarded, wire.UnavailableTooLarge:
	default:
		return fmt.Errorf("%w: unknown unavailable reason %q", ErrBadRequest, res.Unavailable)
	}
	if !ok {
		return nil // no longer tracked
	}
	now := q.o.Now()
	q.mu.Lock()
	if o, live := q.offers[res.Digest]; live && o.node == id.Node {
		delete(q.offers, res.Digest)
	}
	q.mu.Unlock()

	log := q.o.Log.WithValues("node", id.Node, "digest", res.Digest)
	switch {
	case hasSyft:
		return q.ingest(ctx, id, res, img, now, log)
	case res.Failure != "":
		log.Info("node agent could not catalogue the image", "failure", res.Failure)
		_, err := q.o.Store.RecordAgentJobFailure(ctx, res.Digest, id.Node, res.Failure, now, q.o.QuarantineAfter, q.o.QuarantineFor)
		return err
	default:
		return q.unavailable(ctx, id, res, img, now, log)
	}
}

// ingest stores an agent SBOM through the acquirer and records where it came from. A refused document counts
// toward the image's quarantine (at once when the refusal is deterministic); a transient failure is returned.
func (q *WorkQueue) ingest(ctx context.Context, id Identity, res *wire.SBOMResult, img model.Image, now time.Time,
	log logr.Logger) error {
	err := q.o.Acquirer.Ingest(ctx,
		sbom.Request{Repo: img.Repo, Digest: res.Digest, IndexDigest: img.IndexDigest, Platform: img.Platform},
		&sbom.Result{SyftJSON: res.SyftJSON, Coverage: res.Coverage, Source: sbom.SourceAgent})
	switch {
	case err == nil:
		if err := q.o.Store.PutAgentProvenance(ctx, store.AgentProvenance{Digest: res.Digest, Node: id.Node,
			AgentVersion: res.AgentVersion, ReceivedAt: now}); err != nil {
			return err
		}
		log.Info("stored the node agent's SBOM", "agentVersion", res.AgentVersion)
		return q.o.Store.ClearAgentJob(ctx, res.Digest)
	case errors.Is(err, sbom.ErrSuperseded):
		return nil
	}
	kind := sbom.KindOf(err)
	if kind == sbom.FailTransient {
		return err
	}
	after := q.o.QuarantineAfter
	if kind == sbom.FailQuarantine {
		after = 1
	}
	log.Info("node agent SBOM refused", "error", err.Error())
	_, err = q.o.Store.RecordAgentJobFailure(ctx, res.Digest, id.Node, err.Error(), now, after, q.o.QuarantineFor)
	return err
}

// unavailable declines the image for this node for inventory.UnresolvableRetry; it never counts. When the
// node discarded the image's layers and no other node holds it complete, the image's reason says so, which
// stops offering it to any node.
func (q *WorkQueue) unavailable(ctx context.Context, id Identity, res *wire.SBOMResult, img model.Image, now time.Time,
	log logr.Logger) error {
	q.mu.Lock()
	q.declined[declineKey(id.Node, res.Digest)] = now.Add(inventory.UnresolvableRetry)
	q.mu.Unlock()
	log.V(1).Info("node agent cannot catalogue the image", "unavailable", res.Unavailable)
	if res.Unavailable != wire.UnavailableLayersDiscarded {
		return nil
	}
	nodes, err := q.o.Store.AgentNodes(ctx)
	if err != nil {
		return err
	}
	for _, n := range nodes {
		if n.Node == id.Node {
			continue
		}
		rows, err := q.o.Store.NodeImages(ctx, n.Node)
		if err != nil {
			return err
		}
		if heldComplete(rows, res.Digest, img.IndexDigest) {
			return nil
		}
	}
	_, err = q.o.Store.SetImageStatusReason(ctx, res.Digest, inventory.ReasonLayersDiscarded)
	return err
}
