package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
// started sends nothing, and the controller offers the image again once the offer expires.
const minJobShare = 4

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
// its spooled file. A request past its deadline, or with less than 1/minJobShare of its time left, is skipped.
// Nothing is sent when the failure is not the image's: a cataloguer that is not up, or a scratch volume that
// cannot take the staged image or its SBOM (the controller offers the work again).
func (a *agent) runJob(ctx context.Context, w wire.WorkRequest, received time.Time) {
	left := w.Deadline.Sub(a.o.Now())
	if left <= 0 {
		a.o.Log.Info("skipping work past its deadline", "id", w.ID, "digest", w.Digest)
		return
	}
	if left < w.Deadline.Sub(received)/minJobShare {
		a.o.Log.Info("skipping work with too little of its time left; the controller will offer it again", "id", w.ID,
			"digest", w.Digest, "left", left.Round(time.Second))
		return
	}
	a.lease(left + clientTimeout)
	jctx, cancel := context.WithDeadline(ctx, w.Deadline)
	defer cancel()

	res := wire.SBOMResult{ID: w.ID, Node: a.o.NodeName, AgentVersion: version.Version, Digest: w.Digest}
	doc, send := a.job(ctx, jctx, w, &res)
	if doc != nil {
		defer func() { _ = os.Remove(doc.path) }()
	}
	if !send {
		return
	}
	if err := a.client.SBOM(ctx, res, doc); err != nil && ctx.Err() == nil {
		a.logFailure(err, "sending an SBOM result", "id", w.ID, "digest", w.Digest)
	}
}

// job fills res for w and reports whether to send it. doc is the spooled SBOM, when the cataloguer made one.
func (a *agent) job(ctx, jctx context.Context, w wire.WorkRequest, res *wire.SBOMResult) (doc *sbomFile, send bool) {
	if a.store == nil {
		res.Unavailable = wire.UnavailableNotFound
		return nil, true
	}
	t, err := a.store.Resolve(jctx, w.Digest, w.Platform)
	if err != nil {
		return nil, a.stagingFailed(ctx, w, err, res)
	}
	dir := a.workDir(w.ID)
	defer func() { _ = os.RemoveAll(dir) }()
	maxImage := a.maxImageBytes()
	if err := a.store.Stage(jctx, t, dir, maxImage); err != nil {
		return nil, a.stagingFailed(ctx, w, err, res)
	}
	timeout := int(w.Deadline.Sub(a.o.Now()) / time.Second)
	out, err := a.cat.Catalog(jctx, sbom.CatalogRequest{Source: sbom.CatalogSourceOCIDir, Path: dir, Platform: w.Platform,
		MaxBytes: maxImage, TimeoutSeconds: max(timeout, 1)}, a.spoolPath(dir))
	if err != nil {
		if ctx.Err() != nil {
			return nil, false // the agent is stopping: not the image's fault
		}
		var se *catalog.ScratchError
		if errors.As(err, &se) {
			a.o.Log.Error(err, "spooling an SBOM to scratch; the controller will offer the work again", "id", w.ID,
				"digest", w.Digest)
			return nil, false
		}
		kind, msg := workErrorOf(err)
		switch kind {
		case sbom.KindBusy:
			a.o.Log.Info("cataloguer unavailable; the controller will offer the work again", "id", w.ID, "digest", w.Digest)
			return nil, false
		case sbom.KindTooLarge:
			res.Unavailable = wire.UnavailableTooLarge
		default:
			res.Failure = failureDetail(kind, msg)
		}
		return nil, true
	}
	res.Coverage = out.Coverage
	return &sbomFile{path: out.Path, size: out.Size}, true
}

// spoolPath is the scratch file the SBOM of the stage dir dir is spooled to.
func (a *agent) spoolPath(dir string) string {
	return filepath.Join(a.o.Scratch, "sbom-"+filepath.Base(dir)+".json")
}

// stagingFailed maps a Resolve or Stage error onto res, and reports whether to send it.
func (a *agent) stagingFailed(ctx context.Context, w wire.WorkRequest, err error, res *wire.SBOMResult) bool {
	switch {
	case ctx.Err() != nil:
		return false
	case errors.Is(err, contentstore.ErrScratch):
		a.o.Log.Error(err, "staging an image in scratch; the controller will offer the work again", "id", w.ID,
			"digest", w.Digest)
		return false
	case errors.Is(err, contentstore.ErrNotFound):
		res.Unavailable = wire.UnavailableNotFound
	case errors.Is(err, contentstore.ErrLayersDiscarded):
		res.Unavailable = wire.UnavailableLayersDiscarded
	case errors.Is(err, contentstore.ErrTooLarge):
		res.Unavailable = wire.UnavailableTooLarge
	default:
		res.Failure = failureDetail("staging", err.Error())
	}
	return true
}
