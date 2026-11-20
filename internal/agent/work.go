package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/the-it-dept/ffs/internal/agent/contentstore"
	"github.com/the-it-dept/ffs/internal/agentapi/wire"
	"github.com/the-it-dept/ffs/internal/catalog"
	"github.com/the-it-dept/ffs/internal/sbom"
	"github.com/the-it-dept/ffs/internal/version"
)

// safeWorkID matches work IDs that can name a stage dir as they are.
var safeWorkID = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// workDir is the stage dir of one work request: <scratch>/work-<ID>, with an ID that could escape the scratch
// dir replaced by its hash.
func (a *agent) workDir(id string) string {
	if !safeWorkID.MatchString(id) || id == "." || id == ".." {
		sum := sha256.Sum256([]byte(id))
		id = hex.EncodeToString(sum[:8])
	}
	return filepath.Join(a.o.Scratch, "work-"+id)
}

// minJobShare: a job starts only while at least 1/minJobShare of the time its offer gave it is left. Started
// later, it would likely run out of time, and a timeout counts toward the image's quarantine; a job that is not
// started is answered skipped, and the controller offers the image again without counting it.
const minJobShare = 4

// stopSkipTimeout bounds sending the skipped results of the jobs a stopping agent still holds.
const stopSkipTimeout = 5 * time.Second

// resultResends are the waits before each resend of a result the controller did not take; the last one
// repeats. Each is jittered by backoffJitterPercent. Tests shorten them.
var resultResends = []time.Duration{5 * time.Second, 15 * time.Second, 45 * time.Second}

// queuedJob is a work request and when the agent received it: its offer gave it Deadline minus received.
type queuedJob struct {
	w        wire.WorkRequest
	received time.Time
}

// enqueue appends the work of one report, received now.
func (a *agent) enqueue(q []queuedJob, work []wire.WorkRequest) []queuedJob {
	now := a.o.Now()
	for _, w := range work {
		q = append(q, queuedJob{w: w, received: now})
	}
	return q
}

// runJob catalogues one requested image from the content store and posts the result, streaming the SBOM from
// its spooled file. Every request is answered. It is answered skipped, which the controller neither counts
// against the image nor declines, when the agent does not attempt it for a reason that is not the image's: the
// request is past its deadline or has less than 1/minJobShare of its time left, the cataloguer is busy (not up
// yet, or restarting), the scratch volume cannot take the staged image or its SBOM, or the agent is stopping.
func (a *agent) runJob(ctx context.Context, w wire.WorkRequest, received time.Time) {
	left := w.Deadline.Sub(a.o.Now())
	if left <= 0 || left < w.Deadline.Sub(received)/minJobShare {
		a.o.Log.Info("skipping work with too little of its time left; the controller will offer it again", "id", w.ID,
			"digest", w.Digest, "left", left.Round(time.Second))
		a.skip(ctx, w)
		return
	}
	a.lease(left + clientTimeout)
	jctx, cancel := context.WithDeadline(ctx, w.Deadline)
	defer cancel()

	res := wire.SBOMResult{ID: w.ID, Node: a.o.NodeName, AgentVersion: version.Version, Digest: w.Digest}
	doc := a.job(jctx, w, &res)
	if doc != nil {
		defer func() { _ = os.Remove(doc.path) }()
	}
	// The stopping rule lives here alone: whatever the job got to, a stopping agent answers skipped, and the
	// image is offered again.
	if ctx.Err() != nil {
		a.skip(ctx, w)
		return
	}
	a.post(ctx, w, res, doc, true)
}

// skip answers each of ws skipped. While the agent is stopping (ctx has ended), they are sent detached from
// ctx, once each, for at most stopSkipTimeout in all: a resend wait would use up the budget the rest need.
func (a *agent) skip(ctx context.Context, ws ...wire.WorkRequest) {
	resend := true
	if ctx.Err() != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.WithoutCancel(ctx), stopSkipTimeout)
		defer cancel()
		resend = false
	}
	for _, w := range ws {
		a.post(ctx, w, wire.SBOMResult{ID: w.ID, Node: a.o.NodeName, AgentVersion: version.Version, Digest: w.Digest,
			Unavailable: wire.UnavailableSkipped}, nil, resend)
	}
}

// post sends res, the result of w. A result the controller did not take (no answer, 429 or 5xx) would leave
// w unanswered, and an unanswered request counts against its image, so with resend it is sent again after
// each of resultResends in turn, or the controller's Retry-After when longer, while the controller still
// takes a result for w: until wire.ResultGrace after its deadline. Any other answer is final. When the agent
// starts stopping during a resend wait, w is answered skipped once, detached, so it does not count either.
func (a *agent) post(ctx context.Context, w wire.WorkRequest, res wire.SBOMResult, doc *sbomFile, resend bool) {
	until := w.Deadline.Add(wire.ResultGrace)
	for i := 0; ; i++ {
		err := a.client.SBOM(ctx, res, doc)
		if err == nil || ctx.Err() != nil {
			return
		}
		var se *StatusError
		if i > 0 && errors.As(err, &se) && se.Code == http.StatusForbidden {
			// A resend after a lost answer: the controller already stored the result and released w.
			a.o.Log.Info("the controller no longer takes this SBOM result; an earlier send was stored", "id", res.ID, "digest", res.Digest)
			return
		}
		if !resend {
			a.logFailure(err, "sending an SBOM result", "id", res.ID, "digest", res.Digest)
			return
		}
		wait := jittered(resultResends[min(i, len(resultResends)-1)], backoffJitterPercent, a.o.Jitter)
		if errors.As(err, &se) && se.RetryAfter > wait {
			wait = se.RetryAfter
		}
		if !transient(err) || !a.o.Now().Add(wait).Before(until) {
			a.logFailure(err, "sending an SBOM result", "id", res.ID, "digest", res.Digest)
			return
		}
		a.o.Log.Info("the controller did not take an SBOM result; sending it again", "id", res.ID, "digest", res.Digest,
			"retryIn", wait, "reason", err.Error())
		a.lease(wait + clientTimeout)
		if !a.sleepUntil(ctx, a.o.Now().Add(wait)) {
			a.skip(ctx, w)
			return
		}
	}
}

// job fills res for w, within jctx. doc is the spooled SBOM, when the cataloguer made one. When the agent
// stops during the job, runJob answers skipped, whatever res says.
func (a *agent) job(jctx context.Context, w wire.WorkRequest, res *wire.SBOMResult) (doc *sbomFile) {
	if a.store == nil {
		res.Unavailable = wire.UnavailableNotFound
		return nil
	}
	t, err := a.store.Resolve(jctx, w.Digest, w.Platform)
	if err != nil {
		a.stagingFailed(w, err, res)
		return nil
	}
	dir := a.workDir(w.ID)
	defer func() { _ = os.RemoveAll(dir) }()
	maxImage := a.maxImageBytes()
	if err := a.store.Stage(jctx, t, dir, maxImage); err != nil {
		a.stagingFailed(w, err, res)
		return nil
	}
	timeout := int(w.Deadline.Sub(a.o.Now()) / time.Second)
	out, err := a.cat.Catalog(jctx, sbom.CatalogRequest{Source: sbom.CatalogSourceOCIDir, Path: dir, Platform: w.Platform,
		MaxBytes: maxImage, TimeoutSeconds: max(timeout, 1)}, a.spoolPath(dir))
	if err != nil {
		var se *catalog.ScratchError
		kind, msg := workErrorOf(err)
		switch {
		case errors.As(err, &se):
			a.o.Log.Error(err, "spooling an SBOM to scratch; the controller will offer the work again", "id", w.ID,
				"digest", w.Digest)
			res.Unavailable = wire.UnavailableSkipped
		case kind == sbom.KindBusy:
			a.o.Log.Info("cataloguer unavailable; the controller will offer the work again", "id", w.ID, "digest", w.Digest)
			res.Unavailable = wire.UnavailableSkipped
		case kind == sbom.KindTooLarge:
			res.Unavailable = wire.UnavailableTooLarge
		default:
			res.Failure = failureDetail(kind, msg)
		}
		return nil
	}
	res.Coverage = out.Coverage
	return &sbomFile{path: out.Path, size: out.Size}
}

// spoolPath is the scratch file the SBOM of the stage dir dir is spooled to.
func (a *agent) spoolPath(dir string) string {
	return filepath.Join(a.o.Scratch, "sbom-"+filepath.Base(dir)+".json")
}

// stagingFailed maps a Resolve or Stage error onto res.
func (a *agent) stagingFailed(w wire.WorkRequest, err error, res *wire.SBOMResult) {
	switch {
	case errors.Is(err, contentstore.ErrScratch):
		a.o.Log.Error(err, "staging an image in scratch; the controller will offer the work again", "id", w.ID,
			"digest", w.Digest)
		res.Unavailable = wire.UnavailableSkipped
	case errors.Is(err, contentstore.ErrNotFound):
		res.Unavailable = wire.UnavailableNotFound
	case errors.Is(err, contentstore.ErrLayersDiscarded):
		res.Unavailable = wire.UnavailableLayersDiscarded
	case errors.Is(err, contentstore.ErrTooLarge):
		res.Unavailable = wire.UnavailableTooLarge
	default:
		res.Failure = failureDetail("staging", err.Error())
	}
}
