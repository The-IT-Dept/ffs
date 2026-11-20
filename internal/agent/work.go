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

// runJob catalogues one requested image from the content store and posts the result. A request past its
// deadline is skipped; a cataloguer that is not up sends nothing (the controller offers the work again).
func (a *agent) runJob(ctx context.Context, w wire.WorkRequest) {
	if !w.Deadline.After(a.o.Now()) {
		a.o.Log.Info("skipping work past its deadline", "id", w.ID, "digest", w.Digest)
		return
	}
	jctx, cancel := context.WithDeadline(ctx, w.Deadline)
	defer cancel()
	stop := a.keepAlive(jctx)
	defer stop()

	res := wire.SBOMResult{ID: w.ID, Node: a.o.NodeName, AgentVersion: version.Version, Digest: w.Digest}
	if !a.job(ctx, jctx, w, &res) {
		return
	}
	if err := a.client.SBOM(ctx, res); err != nil {
		a.o.Log.Error(err, "sending an SBOM result", "id", w.ID, "digest", w.Digest)
	}
}

// job fills res for w and reports whether to send it.
func (a *agent) job(ctx, jctx context.Context, w wire.WorkRequest, res *wire.SBOMResult) bool {
	if a.store == nil {
		res.Unavailable = wire.UnavailableNotFound
		return true
	}
	t, err := a.store.Resolve(jctx, w.Digest, w.Platform)
	if err != nil {
		return a.stagingFailed(ctx, err, res)
	}
	dir := a.workDir(w.ID)
	defer func() { _ = os.RemoveAll(dir) }()
	maxImage := a.maxImageBytes()
	if err := a.store.Stage(jctx, t, dir, maxImage); err != nil {
		return a.stagingFailed(ctx, err, res)
	}
	timeout := int(w.Deadline.Sub(a.o.Now()) / time.Second)
	resp, err := a.cat.Catalog(jctx, sbom.CatalogRequest{Source: sbom.CatalogSourceOCIDir, Path: dir, Platform: w.Platform,
		MaxBytes: maxImage, TimeoutSeconds: max(timeout, 1)})
	if err != nil {
		if ctx.Err() != nil {
			return false // the agent is stopping: not the image's fault
		}
		kind, msg := workErrorOf(err)
		switch kind {
		case sbom.KindBusy:
			a.o.Log.Info("cataloguer unavailable; the controller will offer the work again", "id", w.ID, "digest", w.Digest)
			return false
		case sbom.KindTooLarge:
			res.Unavailable = wire.UnavailableTooLarge
		default:
			res.Failure = failureDetail(kind, msg)
		}
		return true
	}
	res.SyftJSON, res.Coverage = resp.SyftJSON, resp.Coverage
	return true
}

// stagingFailed maps a Resolve or Stage error onto res.
func (a *agent) stagingFailed(ctx context.Context, err error, res *wire.SBOMResult) bool {
	switch {
	case ctx.Err() != nil:
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
