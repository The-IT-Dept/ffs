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
	// resultGrace is how long after its deadline a request still takes a result: the agent's job ends at the
	// deadline, and its result is posted after that, and again while the controller does not take it.
	resultGrace = wire.ResultGrace
	// reasonOfferExpired is the counted failure of an offer the agent reached but sent no result for: the agent
	// answers every request it reaches, skipped ones included, so its process most likely died cataloguing the
	// image (killed out of memory, say), and an image that keeps doing it is quarantined like one whose
	// cataloguer fails (spec §9.3).
	reasonOfferExpired = "the node agent sent no result before the request expired"
)

// offeredClasses are the unresolvable images a node agent may catalogue from its content store.
var offeredClasses = []model.UnresolvableClass{
	model.UnresolvableSideLoaded, model.UnresolvableAuth, model.UnresolvableUnreachable, model.UnresolvableNotFound,
}

// AgentImageIngest stores an image SBOM one node's agent catalogued, with its provenance; *sbom.Acquirer
// implements it.
type AgentImageIngest interface {
	IngestFromNode(ctx context.Context, prov store.AgentProvenance, r sbom.Request, res *sbom.Result) error
}

var _ AgentImageIngest = (*sbom.Acquirer)(nil)

// WorkOptions configures a WorkQueue.
type WorkOptions struct {
	Store           *store.Store
	Acquirer        AgentImageIngest
	Pods            PodIndex
	PerReport       int           // images offered per report at most; 0 offers none
	Timeout         time.Duration // how long an offer is held for its node
	QuarantineAfter int           // counted failures that quarantine an image; 0: 2
	QuarantineFor   time.Duration // 0: 24h
	Now             func() time.Time
	Log             logr.Logger
}

// WorkQueue offers unresolvable images to the node agents that hold them and accepts the SBOMs they send
// back. Offers live in memory only: after a restart every image is offered afresh. A node holds at most
// PerReport offers before their deadlines, however often it reports, and an offer takes a result until
// resultGrace after its deadline.
//
// The agent answers every request it reaches: with an SBOM, a failure, a reason the image is unavailable, or
// skipped when it did not attempt it for a reason that is not the image's (too little time left, a busy
// cataloguer, a scratch volume that cannot take it, the agent stopping). A skipped request is released
// without counting. So a request that expires unanswered was cut short: the agent process died on it (killed
// out of memory, say), or its result was lost. It counts against its image unless the controller held its
// result up (see ResultWait) or it was queued behind another: an agent process works through its requests one
// at a time, in the order they were offered, so an unanswered offer made while an earlier unanswered offer to
// the same process was still before its deadline was never attempted, and is not counted. Of the requests a
// process held when it died, only the one it died on counts. A restarted agent (a new Instance) starts a new
// queue.
//
// Agents older than 0.0.1-rc.7 send no Instance, so all of a node's processes share one queue: until a rollout
// has replaced them, their requests are accounted per node rather than per process. After such an agent
// restarts, a request made to it while an unanswered request of its previous process was still before its
// deadline is taken as queued behind that one, and is not counted if the agent dies on it; inFlight, too,
// takes the processes for one.
type WorkQueue struct {
	o WorkOptions

	mu       sync.Mutex
	seq      uint64               // the last offer's sequence number
	offers   map[string]offer     // digest → its offer, until it is answered or forget drops it
	seen     map[string]time.Time // digest → when Offer first saw it as offerable work, for oldest-first order
	declined map[string]time.Time // node+"\x00"+digest → when the node may be offered the digest again
	// stalled is, per agent process (node+"\x00"+instance), the latest deadline of an offer to it that
	// expired unanswered: an offer made before then was queued behind that offer.
	stalled map[string]time.Time
}

type offer struct {
	id, node string
	instance string    // the node's agent process (Report.Instance) when the offer was made
	seq      uint64    // offer order: an agent works through its offers in this order
	at       time.Time // when the offer was made
	deadline time.Time
	// answered: a result for the offer arrived but was not stored (a transient failure) or not read because the
	// controller held it up (it waited for the ingest budget too long, or its body could not be read in full
	// after a wait long enough to cut it short). The offer stays, because the agent sends the result again while
	// the offer takes one, and its expiry is not counted against the image.
	answered bool
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
	return &WorkQueue{o: o, offers: map[string]offer{}, seen: map[string]time.Time{}, declined: map[string]time.Time{},
		stalled: map[string]time.Time{}}
}

func declineKey(node, digest string) string { return node + "\x00" + digest }

// agentKey identifies an agent process: its node and Instance. An agent older than 0.0.1-rc.7 sends no
// Instance, so its key is its node's, and its processes share one queue (see WorkQueue).
func agentKey(node, instance string) string { return node + "\x00" + instance }

// Offer picks images for node's agent to catalogue, oldest first, up to PerReport less the node's offers
// before their deadlines: unresolvable images of an offered class that a pod on node runs, that node holds complete, that are
// not offered to any node or declined by this one, and that are not quarantined. It first counts every expired
// offer forget returns, joining the errors of any it could not record.
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
	var errs []error
	for _, e := range q.forget(now, offerable) {
		q.o.Log.Info("node agent sent no result for an image before the request expired", "node", e.node, "digest", e.digest)
		if _, err := q.o.Store.RecordAgentJobFailure(ctx, e.digest, e.node, reasonOfferExpired, now, q.o.QuarantineAfter,
			q.o.QuarantineFor); err != nil {
			errs = append(errs, fmt.Errorf("counting the expired request of %s on %s: %w", e.digest, e.node, err))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
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
	reporting, _, err := q.o.Store.AgentNode(ctx, node) // just written by this report: its agent process
	if err != nil {
		return nil, err
	}

	q.mu.Lock()
	defer q.mu.Unlock()
	room := q.o.PerReport
	for _, o := range q.offers {
		if o.node == node && o.deadline.After(now) {
			room--
		}
	}
	slices.SortFunc(candidates, func(a, b model.Image) int {
		return cmp.Or(q.seen[a.Digest].Compare(q.seen[b.Digest]), cmp.Compare(a.Digest, b.Digest))
	})
	var work []wire.WorkRequest
	for _, img := range candidates {
		if len(work) >= room {
			break
		}
		if _, ok := q.offers[img.Digest]; ok { // live, or past its deadline but still taking a result
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
		o := q.hold(img.Digest, id, node, reporting.Instance, now)
		work = append(work, wire.WorkRequest{ID: id, Digest: img.Digest, Platform: img.Platform, Deadline: o.deadline})
	}
	return work, nil
}

// hold records an offer of digest to node's agent process, made at now. The caller holds q.mu.
func (q *WorkQueue) hold(digest, id, node, instance string, now time.Time) offer {
	q.seq++
	o := offer{id: id, node: node, instance: instance, seq: q.seq, at: now, deadline: now.Add(q.o.Timeout)}
	q.offers[digest] = o
	return o
}

// expiredOffer is an offer forget counts against its image.
type expiredOffer struct{ digest, node string }

// forget records when each offerable digest was first seen, and drops what is no longer needed: the order of
// digests that are no longer offerable, offers resultGrace past their deadline, expired declines and stalls
// no recorded offer can be behind. It returns the expired offers to count: unanswered, of a digest still
// offerable, and the first unanswered offer of their agent process, not one queued behind it (see WorkQueue).
func (q *WorkQueue) forget(now time.Time, offerable map[string]bool) []expiredOffer {
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
	type unanswered struct {
		digest string
		offer
	}
	var expired []unanswered
	for d, o := range q.offers {
		if o.deadline.Add(resultGrace).After(now) {
			continue
		}
		delete(q.offers, d)
		if !o.answered {
			expired = append(expired, unanswered{d, o})
		}
	}
	// In offer order, so every earlier offer to the same agent process is settled first: an offer to the same
	// process expires no later than the ones made after it.
	slices.SortFunc(expired, func(a, b unanswered) int { return cmp.Compare(a.seq, b.seq) })
	var count []expiredOffer
	for _, e := range expired {
		k := agentKey(e.node, e.instance)
		behind := q.stalled[k].After(e.at)
		if e.deadline.After(q.stalled[k]) {
			q.stalled[k] = e.deadline
		}
		if !behind && offerable[e.digest] {
			count = append(count, expiredOffer{digest: e.digest, node: e.node})
		}
	}
	for k, until := range q.stalled {
		// Every offer made before until has a deadline before until+Timeout, so it has been settled by then
		// plus the grace.
		if !until.Add(q.o.Timeout + resultGrace).After(now) {
			delete(q.stalled, k)
		}
	}
	for k, until := range q.declined {
		if !until.After(now) {
			delete(q.declined, k)
		}
	}
	return count
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

// SBOM applies a node agent's result for one image. It is accepted only for an offer of the image to that
// node that still takes a result: one Offer made to the node, no more than resultGrace past its deadline.
// Anything else is ErrForbidden with nothing written, so a node cannot supply, fail, decline or skip an image
// it was not asked for. A handled result releases the offer; a skipped one is released without counting and
// leaves the image offerable. A transient failure keeps the offer, marked answered, and is answered 500: the
// agent sends the result again while the offer takes one, and the offer's expiry is not counted against the
// image.
func (q *WorkQueue) SBOM(ctx context.Context, id Identity, res *wire.SBOMResult) error {
	if res.Node != id.Node {
		return fmt.Errorf("%w: result is for node %s, not %s", ErrForbidden, res.Node, id.Node)
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
	case "", wire.UnavailableNotFound, wire.UnavailableLayersDiscarded, wire.UnavailableTooLarge, wire.UnavailableSkipped:
	default:
		return fmt.Errorf("%w: unknown unavailable reason %q", ErrBadRequest, res.Unavailable)
	}
	now := q.o.Now()
	q.mu.Lock()
	o, live := q.offers[res.Digest]
	q.mu.Unlock()
	if !live || o.node != id.Node || !o.deadline.Add(resultGrace).After(now) {
		return fmt.Errorf("%w: %s was not offered to %s, or its offer has expired", ErrForbidden, res.Digest, id.Node)
	}
	log := q.o.Log.WithValues("node", id.Node, "digest", res.Digest)
	if res.Unavailable == wire.UnavailableSkipped {
		log.V(1).Info("node agent skipped the image; it is offered again")
		q.release(res.Digest, o.id)
		return nil
	}
	img, ok, err := q.o.Store.GetImage(ctx, res.Digest)
	if err == nil && ok {
		switch {
		case hasSyft:
			err = q.ingest(ctx, id, res, img, now, log)
		case res.Failure != "":
			log.Info("node agent could not catalogue the image", "failure", res.Failure)
			_, err = q.o.Store.RecordAgentJobFailure(ctx, res.Digest, id.Node, res.Failure, now, q.o.QuarantineAfter, q.o.QuarantineFor)
		default:
			err = q.unavailable(ctx, id, res, img, now, log)
		}
	}
	if err != nil && !errors.Is(err, ErrForbidden) { // transient: the offer stays for the agent's retry
		q.markAnswered(res.Digest, o.id)
		return err
	}
	q.release(res.Digest, o.id)
	return err
}

// release drops the offer id of digest, unless another offer has replaced it.
func (q *WorkQueue) release(digest, id string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if cur, ok := q.offers[digest]; ok && cur.id == id {
		delete(q.offers, digest)
	}
}

// ResultWait is how long a result from node answering the request id may wait for the ingest budget before
// it is read, and what to call when the controller held it up: the time until that request stops taking a
// result, and unread, which the server calls when the result waited that long unread or its body could not be
// read in full after a long wait, marks that request answered, because the controller held its result up, not
// the image.
// Only that request is marked: the requests the agent has not reached yet need answers of their own, and one
// it dies on still counts. A request marked answered keeps taking a result, as the agent sends a result again
// after a 5xx (the 503 for a result not read included), a 429 or no answer while its request takes one. wait
// is zero or less when the request takes no result: not an offer to node, past its grace, or released.
//
// id is the request ID the agent sends in wire.HeaderWorkID. Older agents send none, and never send a result
// twice: their result answers the request they are on, which inFlight finds.
func (q *WorkQueue) ResultWait(node, id string) (wait time.Duration, unread func()) {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.o.Now()
	var digest string
	var target offer
	if id == "" {
		digest, target = q.inFlight(node, now)
	} else {
		for d, o := range q.offers {
			if o.id == id && o.node == node {
				digest, target = d, o
				break
			}
		}
	}
	if digest == "" || !target.deadline.Add(resultGrace).After(now) {
		return 0, func() {}
	}
	return target.deadline.Add(resultGrace).Sub(now), func() { q.markAnswered(digest, target.id) }
}

// inFlight is the request a result from node's agent answers when the agent does not name it: an agent process
// answers its requests one at a time, in the order they were offered, and the node's newest process (the one
// its latest offer went to) is the one working, so it is that process's earliest unanswered request that still
// takes a result. Failing such a request, it is the earliest of the node's other requests that still take a
// result. digest is "" when none does. The caller holds q.mu.
func (q *WorkQueue) inFlight(node string, now time.Time) (digest string, target offer) {
	var newest offer
	for _, o := range q.offers {
		if o.node == node && o.seq > newest.seq {
			newest = o
		}
	}
	// inFlightFirst orders the requests a result from node most likely answers: the newest process's first,
	// then unanswered ones, then in offer order.
	inFlightFirst := func(a, b offer) int {
		return cmp.Or(falseFirst(a.instance != newest.instance, b.instance != newest.instance),
			falseFirst(a.answered, b.answered), cmp.Compare(a.seq, b.seq))
	}
	for d, o := range q.offers {
		if o.node != node || !o.deadline.Add(resultGrace).After(now) {
			continue
		}
		if digest == "" || inFlightFirst(o, target) < 0 {
			digest, target = d, o
		}
	}
	return digest, target
}

// falseFirst orders false before true.
func falseFirst(a, b bool) int {
	switch {
	case a == b:
		return 0
	case !a:
		return -1
	}
	return 1
}

// markAnswered marks the offer id of digest answered, unless another offer has replaced it: a result for it
// arrived but was not handled, so its expiry is not counted against the image.
func (q *WorkQueue) markAnswered(digest, id string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if cur, ok := q.offers[digest]; ok && cur.id == id {
		cur.answered = true
		q.offers[digest] = cur
	}
}

// ingest stores an agent SBOM, with where it came from, through the acquirer. A refused document counts
// toward the image's quarantine (at once when the refusal is deterministic); a transient failure is returned.
// An image already catalogued from another node's agent SBOM is ErrForbidden: it is never replaced.
func (q *WorkQueue) ingest(ctx context.Context, id Identity, res *wire.SBOMResult, img model.Image, now time.Time,
	log logr.Logger) error {
	err := q.o.Acquirer.IngestFromNode(ctx,
		store.AgentProvenance{Digest: res.Digest, Node: id.Node, AgentVersion: res.AgentVersion, ReceivedAt: now},
		sbom.Request{Repo: img.Repo, Digest: res.Digest, IndexDigest: img.IndexDigest, Platform: img.Platform},
		&sbom.Result{SyftJSON: res.SyftJSON, Coverage: res.Coverage, Source: sbom.SourceAgent})
	switch {
	case err == nil:
		log.Info("stored the node agent's SBOM", "agentVersion", res.AgentVersion)
		return q.o.Store.ClearAgentJob(ctx, res.Digest)
	case errors.Is(err, sbom.ErrSuperseded):
		return nil
	case errors.Is(err, sbom.ErrOtherNode):
		log.Info("node agent SBOM refused: the image is catalogued from another node's SBOM")
		return fmt.Errorf("%w: %s is catalogued from another node's SBOM", ErrForbidden, res.Digest)
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
	held, err := q.o.Store.HeldCompleteElsewhere(ctx, res.Digest, img.IndexDigest, id.Node)
	if err != nil || held {
		return err
	}
	_, err = q.o.Store.SetImageStatusReason(ctx, res.Digest, inventory.ReasonLayersDiscarded)
	return err
}
