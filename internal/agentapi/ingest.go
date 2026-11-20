package agentapi

import (
	"context"
	"fmt"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"golang.org/x/sync/semaphore"
	"golang.org/x/sync/singleflight"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/the-it-dept/ffs/internal/agentapi/wire"
	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/nodegroup"
	"github.com/the-it-dept/ffs/internal/output/metrics"
	"github.com/the-it-dept/ffs/internal/sbom"
	"github.com/the-it-dept/ffs/internal/store"
)

const (
	// hostConcurrency bounds the host documents decoded into Syft models at once. The server's ingest
	// budget bounds the report bodies held meanwhile, and a report keeps its share of it while its host
	// part is prepared here.
	hostConcurrency = 2
	// hostKeyPrefix keys a node's host processing in acquisitions_inflight and agent_jobs.
	hostKeyPrefix = "nodehost:"
	// hostQuarantineAfter counted failures quarantine a node's host inventory for hostQuarantineFor.
	hostQuarantineAfter = 2
	hostQuarantineFor   = 24 * time.Hour
	// reasonHostStale is the counted failure of a host acquisition the controller never ended.
	reasonHostStale = "the controller stopped while processing the host inventory"
	// hostStoreTimeout bounds storing one group's host SBOM. The store runs detached from the request that
	// started it, since other nodes' reports of the same fingerprint wait on it.
	hostStoreTimeout = 2 * time.Minute
)

// AgentIngest stores an agent-catalogued SBOM; *sbom.Acquirer implements it.
type AgentIngest interface {
	Ingest(ctx context.Context, r sbom.Request, res *sbom.Result) error
}

var _ AgentIngest = (*sbom.Acquirer)(nil)

// NodeReader reads a Node from the manager's cache.
type NodeReader interface {
	GetNode(ctx context.Context, name string) (*corev1.Node, bool, error)
}

type nodeReader struct{ r client.Reader }

// NewNodeReader returns a NodeReader over r. A node that does not exist is (nil, false, nil).
func NewNodeReader(r client.Reader) NodeReader { return nodeReader{r: r} }

func (n nodeReader) GetNode(ctx context.Context, name string) (*corev1.Node, bool, error) {
	var node corev1.Node
	if err := n.r.Get(ctx, client.ObjectKey{Name: name}, &node); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return &node, true, nil
}

// Offerer hands out image work for a node; *WorkQueue implements it.
type Offerer interface {
	Offer(ctx context.Context, node string) ([]wire.WorkRequest, error)
}

// IngesterOptions configures an Ingester. Work and Trigger may be nil.
type IngesterOptions struct {
	Store    *store.Store
	Acquirer AgentIngest
	Nodes    NodeReader
	Work     Offerer
	Trigger  func()
	Config   config.NodeAgentConfig
	Now      func() time.Time
	Log      logr.Logger
}

// Ingester applies agent reports: the node's status row, its host SBOM (stored once per fingerprint under
// nodegroup:<fingerprint>), its group description and its cached images.
type Ingester struct {
	o       IngesterOptions
	slots   *semaphore.Weighted
	flight  singleflight.Group
	prepare func(r *wire.Report, n *corev1.Node, now time.Time) (hostPrep, error) // prepareHost; tests count calls
	// flightJoined, when set, is called once a report has started the store of its fingerprint's group SBOM
	// or joined one in progress, before it waits for the outcome; tests use it.
	flightJoined func(node string)

	mu   sync.Mutex
	busy map[string]bool // nodes whose host inventory this process is processing
}

// NewIngester returns an Ingester.
func NewIngester(o IngesterOptions) *Ingester {
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Ingester{o: o, slots: semaphore.NewWeighted(hostConcurrency), prepare: prepareHost, busy: map[string]bool{}}
}

// hostGate is the outcome of the host gate: a prepared host, or why host processing was skipped.
type hostGate struct {
	prep    *hostPrep
	prepErr error  // the host SBOM could not be prepared
	skipErr string // last_error to write for a skipped host (quarantine)
	end     func() // ends the host acquisition record and frees the node
}

// Report applies one report (see Contract › Data flows › Report). A duplicate writes nothing and answers
// Applied false. A full report whose host part was not stored for a reason that may pass (a transient
// failure, the node's host part already in progress, or a duplicate that lost the race to an earlier copy)
// answers HostRetry, so the agent resends it on its backoff rather than in reportInterval.
func (i *Ingester) Report(ctx context.Context, id Identity, r *wire.Report) (wire.ReportResponse, error) {
	cfg := WireConfig(i.o.Config)
	if r.Kind != wire.KindFull && r.Kind != wire.KindImages {
		return wire.ReportResponse{}, fmt.Errorf("%w: unknown report kind %q", ErrBadRequest, r.Kind)
	}
	node, ok, err := i.o.Nodes.GetNode(ctx, id.Node)
	if err != nil {
		return wire.ReportResponse{}, fmt.Errorf("reading node %s: %w", id.Node, err)
	}
	if !ok {
		return wire.ReportResponse{}, fmt.Errorf("%w: node %s is not in the cluster", ErrForbidden, id.Node)
	}
	row, found, err := i.o.Store.AgentNode(ctx, id.Node)
	if err != nil {
		return wire.ReportResponse{}, err
	}
	var stored *store.AgentNode
	if found {
		stored = &row
	}
	rep := store.AgentReport{Node: id.Node, AgentVersion: r.AgentVersion, BootID: r.BootID, Instance: r.Instance,
		StartedAt: r.StartedAt, Seq: r.Seq}
	if stored != nil && rep.DuplicateOf(*stored) {
		metrics.AgentReports.WithLabelValues(metrics.AgentReportDuplicate, "").Inc()
		return wire.ReportResponse{Applied: false, Config: cfg}, nil
	}

	now := i.o.Now()
	var gate hostGate
	if r.Kind == wire.KindFull && r.Host != nil {
		if gate, err = i.hostGate(ctx, id.Node, r, node, now); err != nil {
			return wire.ReportResponse{}, err
		}
		defer gate.end()
	}

	rep.At, rep.Full, rep.KernelRelease, rep.Arch = now, r.Kind == wire.KindFull, r.KernelRelease, r.Arch
	if gate.prep != nil {
		rep.RebootPending, rep.RebootReason, rep.PackageDB = gate.prep.Split.RebootPending, gate.prep.Split.RebootReason, r.Host.PackageDB
	} else if stored != nil {
		// A skipped or failed host part must not clear the reboot-pending signal (spec §9.4).
		rep.RebootPending, rep.RebootReason, rep.PackageDB = stored.RebootPending, stored.RebootReason, stored.PackageDB
	}
	var storedGaps []model.NodeCoverageGap
	if stored != nil {
		storedGaps = stored.Coverage
	}
	var osr *osRelease
	if gate.prep != nil {
		osr = gate.prep.OS
	}
	rep.Coverage = coverageOf(r, storedGaps, imageBasedOS(osr, node.Status.NodeInfo.OSImage))
	for _, p := range r.Problems {
		rep.Problems = append(rep.Problems, problemText(p))
	}
	applied, err := i.o.Store.AcceptAgentReport(ctx, rep)
	if err != nil {
		return wire.ReportResponse{}, err
	}
	if !applied {
		// An earlier copy of this report was applied while this one prepared its host part, so this one's host
		// part is not stored: the agent sends it again rather than waiting reportInterval.
		metrics.AgentReports.WithLabelValues(metrics.AgentReportDuplicate, "").Inc()
		return wire.ReportResponse{Applied: false, HostRetry: gate.prep != nil, Config: cfg}, nil
	}
	metrics.AgentReports.WithLabelValues(metrics.AgentReportApplied, "").Inc()

	hostRetry, err := i.storeHost(ctx, id.Node, r, gate, now)
	if err != nil {
		return wire.ReportResponse{}, err
	}
	if r.Images != nil {
		if err := i.o.Store.ReplaceNodeImages(ctx, id.Node, nodeImages(r.Images, node.Status.Images)); err != nil {
			return wire.ReportResponse{}, err
		}
	}
	if i.o.Trigger != nil {
		i.o.Trigger()
	}
	resp := wire.ReportResponse{Applied: true, HostRetry: hostRetry, Config: cfg}
	if i.o.Work != nil {
		work, err := i.o.Work.Offer(ctx, id.Node)
		if err != nil {
			i.o.Log.Error(err, "offering image work", "node", id.Node)
		} else {
			resp.Work = work
		}
	}
	return resp, nil
}

// hostGate decides whether this report's host part is processed and prepares it. A node already in host
// processing here is skipped uncounted; a quarantined one is skipped with the quarantine as its error; an
// acquisition record left by a stopped controller counts toward quarantine. The returned end must be called
// once the host part is stored. When hostGate returns an error or panics, it ends the acquisition record and
// frees the node itself.
func (i *Ingester) hostGate(ctx context.Context, node string, r *wire.Report, n *corev1.Node, now time.Time) (hostGate, error) {
	i.mu.Lock()
	if i.busy[node] {
		i.mu.Unlock()
		return hostGate{end: func() {}}, nil
	}
	i.busy[node] = true
	i.mu.Unlock()

	hk := hostKeyPrefix + node
	acquired, handed := false, false
	end := func() {
		if acquired {
			if err := i.o.Store.EndAcquire(context.WithoutCancel(ctx), hk); err != nil {
				i.o.Log.Error(err, "ending the host acquisition record", "node", node)
			}
		}
		i.mu.Lock()
		delete(i.busy, node)
		i.mu.Unlock()
	}
	// net/http recovers a handler's panic, so neither an error nor a panic may leave the node busy (its host
	// reports skipped for good) or its acquisition record open.
	defer func() {
		if !handed {
			end()
		}
	}()
	handOver := func(g hostGate) (hostGate, error) {
		g.end, handed = end, true
		return g, nil
	}

	job, ok, err := i.o.Store.AgentJobOf(ctx, hk)
	if err != nil {
		return hostGate{}, err
	}
	if ok && job.QuarantinedUntil.After(now) {
		return handOver(hostGate{skipErr: quarantineText(job)})
	}
	stale, err := i.o.Store.BeginAcquire(ctx, hk, now)
	if err != nil {
		return hostGate{}, err
	}
	acquired = true
	if stale {
		job, err := i.o.Store.RecordAgentJobFailure(ctx, hk, node, reasonHostStale, now, hostQuarantineAfter, hostQuarantineFor)
		if err != nil {
			return hostGate{}, err
		}
		if job.QuarantinedUntil.After(now) {
			return handOver(hostGate{skipErr: quarantineText(job)})
		}
	}
	prep, err := i.prepareInSlot(ctx, hk, node, r, n, now)
	if err != nil {
		return hostGate{}, err
	}
	return handOver(prep)
}

// prepareInSlot prepares the host SBOM while holding one of the hostConcurrency slots. A host SBOM that
// cannot be prepared is kept as prepErr: the report still counts as a heartbeat. A panic while preparing is a
// prepErr too, and it is counted toward the host's quarantine: net/http would recover it uncounted, so one
// document that panics the decoder would otherwise be decoded again on every full report.
func (i *Ingester) prepareInSlot(ctx context.Context, hk, node string, r *wire.Report, n *corev1.Node, now time.Time) (hostGate, error) {
	if err := i.slots.Acquire(ctx, 1); err != nil {
		return hostGate{}, err
	}
	panicked := false
	prep, perr := func() (_ hostPrep, err error) {
		defer i.slots.Release(1)
		defer func() {
			if p := recover(); p != nil {
				panicked, err = true, fmt.Errorf("panic: %v", p)
				i.o.Log.Error(err, "preparing the host inventory panicked", "node", node, "stack", string(debug.Stack()))
			}
		}()
		return i.prepare(r, n, now)
	}()
	if panicked {
		if _, err := i.o.Store.RecordAgentJobFailure(ctx, hk, node, "preparing the host inventory: "+perr.Error(), now,
			hostQuarantineAfter, hostQuarantineFor); err != nil {
			return hostGate{}, err
		}
	}
	gate := hostGate{prepErr: perr}
	if perr == nil {
		gate.prep = &prep
	}
	return gate, nil
}

// hostNotSent is the last error of a full report that carried no host inventory, with the agent's catalog
// and scratch problems, which say why.
func hostNotSent(problems []wire.Problem) string {
	var why []string
	for _, p := range problems {
		if p.Code == wire.ProblemCatalog || p.Code == wire.ProblemScratch {
			why = append(why, problemText(p))
		}
	}
	if len(why) == 0 {
		return "host inventory not sent with the full report"
	}
	return "host inventory not collected: " + strings.Join(why, "; ")
}

func quarantineText(job store.AgentJob) string {
	return fmt.Sprintf("host inventory quarantined until %s: %s", job.QuarantinedUntil.UTC().Format(time.RFC3339), job.LastError)
}

// storeHost writes the host part of an applied full report: the group SBOM once per fingerprint, then the
// node's fingerprint, then the group row. On failure the node keeps its current group. retry says the host
// part was not stored for a reason that may pass: another report of the node is processing it, or a
// transient failure.
func (i *Ingester) storeHost(ctx context.Context, node string, r *wire.Report, gate hostGate, now time.Time) (retry bool, err error) {
	st := i.o.Store
	switch {
	case r.Kind != wire.KindFull:
		return false, nil
	case r.Host == nil:
		// The node shows host_not_inventoried with this text until a full report carries its host part.
		return false, st.SetAgentError(ctx, node, hostNotSent(r.Problems))
	case gate.skipErr != "":
		return false, st.SetAgentError(ctx, node, gate.skipErr)
	case gate.prepErr != nil:
		return false, st.SetAgentError(ctx, node, "host inventory could not be read: "+gate.prepErr.Error())
	case gate.prep == nil:
		return true, nil // already being processed by another report of this node
	}
	prep := gate.prep
	hk := hostKeyPrefix + node
	flight := i.flight.DoChan(prep.Fingerprint, func() (ingested any, err error) {
		// Detached from the request that leads: every report of this fingerprint waits on it, so a leader
		// that disconnects must not fail them.
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), hostStoreTimeout)
		defer cancel()
		// A panic is a counted failure, so a document that panics the acquirer is quarantined rather than
		// stored again on every full report.
		defer func() {
			if p := recover(); p != nil {
				ingested, err = false, &sbom.AcquireError{Kind: sbom.FailCounted, Reason: "storing the host inventory panicked",
					Err: fmt.Errorf("%v", p)}
				i.o.Log.Error(err, "storing the host inventory panicked", "node", node, "stack", string(debug.Stack()))
			}
		}()
		digest := nodegroup.GroupDigest(prep.Fingerprint)
		img, ok, err := st.GetImage(fctx, digest)
		if err != nil {
			return false, &sbom.AcquireError{Kind: sbom.FailTransient, Reason: "reading the image", Err: err}
		}
		if ok && img.Status == model.ImageCatalogued {
			return false, nil
		}
		return true, i.o.Acquirer.Ingest(fctx, sbom.Request{Repo: model.HostRepo, Digest: digest, Platform: "linux/" + r.Arch},
			&sbom.Result{SyftJSON: prep.SyftJSON, Source: sbom.SourceAgent})
	})
	if i.flightJoined != nil {
		i.flightJoined(node)
	}
	res := <-flight
	v, err := res.Val, res.Err
	if err != nil {
		if werr := st.SetAgentError(ctx, node, "host inventory not stored: "+err.Error()); werr != nil {
			return false, werr
		}
		quarantineAfter := 0
		switch sbom.KindOf(err) {
		case sbom.FailTransient:
			retry = true
		case sbom.FailQuarantine:
			quarantineAfter = 1
		default:
			quarantineAfter = hostQuarantineAfter
		}
		if quarantineAfter > 0 {
			if _, werr := st.RecordAgentJobFailure(ctx, hk, node, err.Error(), now, quarantineAfter, hostQuarantineFor); werr != nil {
				return false, werr
			}
		}
		i.o.Log.Info("host inventory not stored", "node", node, "error", err.Error())
		return retry, nil
	}
	if err := st.SetAgentFingerprint(ctx, node, prep.Fingerprint); err != nil {
		return false, err
	}
	if ingested, _ := v.(bool); ingested {
		if err := st.SetAgentError(ctx, node, ""); err != nil {
			return false, err
		}
	}
	if err := st.PutNodeGroup(ctx, prep.Group, now); err != nil {
		return false, err
	}
	return false, st.ClearAgentJob(ctx, hk)
}
