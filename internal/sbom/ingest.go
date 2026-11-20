package sbom

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/registry"
	"github.com/the-it-dept/ffs/internal/store"
)

// SourceAgent is the Result and image Source of an SBOM a node agent catalogued.
const SourceAgent = "agent"

// ErrSuperseded means Ingest was refused because the image is already catalogued from another
// source: a registry SBOM is never replaced by an agent one.
var ErrSuperseded = errors.New("sbom: image already catalogued from a registry source")

// ErrOtherNode means IngestFromNode was refused because the image is already catalogued from an SBOM
// another node's agent supplied: one node never replaces the image inventory another node supplied.
var ErrOtherNode = errors.New("sbom: image already catalogued from another node's agent")

const (
	// reasonInProgress is the transient refusal of a digest that is queued, running or being ingested.
	reasonInProgress = "an acquisition of the image is in progress"
	// ingestQueue is how many ingested digests can wait for their match.
	ingestQueue = 256
)

// Ingest stores an SBOM a node agent catalogued (res.Source must be SourceAgent) through the same
// path as a source result: size cap, decode, Normalize, PutSBOM, MarkUnmatched and the image
// catalogued with Source "agent". Matching is not done here: the digest is handed to the goroutine
// Start runs, which matches one image at a time, detached from ctx, within MatchTimeout. A digest
// whose match is not handed over (the queue is full, or the controller stops) stays marked unmatched,
// so the hourly sweep or the next start matches it.
//
// Nothing is written when it fails:
//   - ErrSuperseded: the image is catalogued from a source other than "agent";
//   - ErrOtherNode (IngestFromNode only): the image is catalogued from another node's agent SBOM;
//   - an *AcquireError of kind FailTransient with Reason reasonInProgress: the digest is queued,
//     running or being ingested. It must not be counted against the image;
//   - FailCounted with Reason reasonControllerStopped: an acquisition of the digest was recorded and
//     never ended (the controller stopped during it);
//   - FailQuarantine: the SBOM is over MaxSBOMBytes;
//   - FailCounted with Reason "decoding SBOM": the SBOM does not decode;
//   - FailTransient: a store failure;
//   - a plain error when res is nil or its Source is not SourceAgent.
//
// Ingest is for SBOMs no single node owns (a node group's host SBOM); IngestFromNode is for an image
// SBOM one node's agent catalogued.
func (a *Acquirer) Ingest(ctx context.Context, r Request, res *Result) error {
	return a.ingest(ctx, nil, r, res)
}

// IngestFromNode is Ingest for an image SBOM the agent on prov.Node catalogued. It is also refused with
// ErrOtherNode, writing nothing, when the image is already catalogued from an agent SBOM whose recorded
// provenance names another node; a registry SBOM still replaces any agent SBOM (Supersede). A stored
// SBOM records prov (its Digest set to r.Digest) as the image's agent provenance, under the same claim
// on the digest as the check.
func (a *Acquirer) IngestFromNode(ctx context.Context, prov store.AgentProvenance, r Request, res *Result) error {
	if prov.Node == "" {
		return errors.New("sbom: ingest: no node")
	}
	prov.Digest = r.Digest
	return a.ingest(ctx, &prov, r, res)
}

// ingest is Ingest and IngestFromNode; prov is nil for Ingest.
func (a *Acquirer) ingest(ctx context.Context, prov *store.AgentProvenance, r Request, res *Result) error {
	switch {
	case res == nil:
		return errors.New("sbom: ingest: no result")
	case res.Source != SourceAgent:
		return fmt.Errorf("sbom: ingest: result source %q is not %q", res.Source, SourceAgent)
	}
	a.mu.Lock()
	if a.jobs[r.Digest] != nil || a.ingesting[r.Digest] {
		a.mu.Unlock()
		return &AcquireError{Kind: FailTransient, Reason: reasonInProgress}
	}
	a.ingesting[r.Digest] = true
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		delete(a.ingesting, r.Digest)
		a.mu.Unlock()
	}()

	st := a.o.Store
	stale, err := st.BeginAcquire(ctx, r.Digest, a.o.Now())
	if err != nil {
		return storeErr("recording the acquisition", err)
	}
	defer a.bookkeep(ctx, "ending acquisition record", r.Digest, st.EndAcquire)
	if stale {
		return &AcquireError{Kind: FailCounted, Reason: reasonControllerStopped}
	}
	img, ok, err := st.GetImage(ctx, r.Digest)
	if err != nil {
		return storeErr("reading the image", err)
	}
	if ok && img.Status == model.ImageCatalogued && img.Source != SourceAgent {
		return ErrSuperseded
	}
	if ok && img.Status == model.ImageCatalogued && prov != nil {
		// Checked under the digest's ingest claim, so no other node's SBOM lands between the check and the write.
		stored, has, err := st.AgentProvenanceOf(ctx, r.Digest)
		if err != nil {
			return storeErr("reading the agent provenance", err)
		}
		if has && stored.Node != prov.Node {
			return ErrOtherNode
		}
	}
	if _, err := a.store(ctx, img, r, res); err != nil {
		return err
	}
	if prov != nil {
		if err := st.PutAgentProvenance(ctx, *prov); err != nil {
			return storeErr("recording the agent provenance", err)
		}
	}
	select {
	case a.ingested <- r.Digest:
	default:
		a.o.Log.Info("too many ingested images wait for their match; the hourly sweep matches this one", "digest", r.Digest)
	}
	return nil
}

// matchIngested matches an ingested digest unless its match has already completed (the start or
// hourly sweep got to it first).
func (a *Acquirer) matchIngested(ctx context.Context, digest string) {
	un, err := a.o.Store.UnmatchedDigests(ctx, []string{digest})
	if err != nil {
		if ctx.Err() == nil {
			a.o.Log.Error(err, "reading whether an ingested image is matched", "digest", digest)
		}
		return
	}
	if slices.Contains(un, digest) {
		a.match(ctx, digest)
	}
}

// supersede tries the sources for an image catalogued from an agent SBOM (a Supersede request). A
// result replaces the agent SBOM, clears the agent provenance and is matched. Any failure is logged
// and writes nothing: the image is not counted, quarantined or retried, so the agent SBOM stands.
// An acquisition left over from a controller that stopped is ended without trying the sources, so an
// SBOM that takes the controller down is tried at most once per supersede window.
func (a *Acquirer) supersede(ctx context.Context, img model.Image, r Request) (*Result, time.Duration, error) {
	st := a.o.Store
	stale, err := st.BeginAcquire(ctx, r.Digest, a.o.Now())
	if err != nil {
		return a.supersedeFailed(r, storeErr("recording the acquisition", err))
	}
	defer a.bookkeep(ctx, "ending acquisition record", r.Digest, st.EndAcquire)
	if stale {
		return a.supersedeFailed(r, &AcquireError{Kind: FailCounted, Reason: reasonControllerStopped})
	}
	jctx, cancel := context.WithTimeout(registry.LowPriority(ctx), a.o.JobTimeout)
	defer cancel()
	res, err := a.acquire(jctx, r)
	if err == nil {
		res, err = a.store(ctx, img, r, res)
	}
	if err != nil {
		return a.supersedeFailed(r, err)
	}
	if err := st.ClearAgentProvenance(ctx, r.Digest); err != nil {
		a.o.Log.Error(err, "clearing the agent provenance of a superseded image", "digest", r.Digest)
	}
	a.match(ctx, r.Digest)
	return res, 0, nil
}

// supersedeFailed logs a failed supersede and returns err with no retry.
func (a *Acquirer) supersedeFailed(r Request, err error) (*Result, time.Duration, error) {
	a.o.Log.Info("replacing an agent SBOM from the image's sources failed; the agent SBOM stands",
		"digest", r.Digest, "reason", err.Error())
	return nil, 0, err
}
