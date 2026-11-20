package agent

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/agent/contentstore/contentstoretest"
	"github.com/the-it-dept/ffs/internal/agentapi/wire"
	"github.com/the-it-dept/ffs/internal/catalog"
	"github.com/the-it-dept/ffs/internal/sbom"
	"github.com/the-it-dept/ffs/internal/version"
)

// nextSBOM returns the next SBOM result the controller received.
func (c *fakeController) nextSBOM(t *testing.T) wire.SBOMResult {
	t.Helper()
	select {
	case r := <-c.sboms:
		return r
	case <-time.After(waitFor):
		t.Fatal("no SBOM result arrived")
	}
	return wire.SBOMResult{}
}

// noSBOM fails when the controller received an SBOM result.
func (c *fakeController) noSBOM(t *testing.T) {
	t.Helper()
	select {
	case r := <-c.sboms:
		t.Fatalf("unexpected SBOM result %+v", r)
	default:
	}
}

// workDirs lists the work-* dirs left in the scratch dir.
func workDirs(t *testing.T, scratch string) []string {
	t.Helper()
	entries, err := os.ReadDir(scratch)
	require.NoError(t, err)
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "work-") {
			out = append(out, e.Name())
		}
	}
	return out
}

// newTestAgent builds the agent Run would, for driving jobs directly.
func newTestAgent(t *testing.T, e *env) *agent {
	t.Helper()
	a, err := newAgent(context.Background(), e.opts)
	require.NoError(t, err)
	return a
}

func TestWork_CataloguesStagedImageAndCleansUp(t *testing.T) {
	e := newEnv(t)
	platform := "linux/" + runtime.GOARCH
	type seen struct {
		req             sbom.CatalogRequest
		layout, indexOK bool
	}
	jobs := make(chan seen, 10)
	e.runner.setFn(func(_ context.Context, req sbom.CatalogRequest) (*sbom.CatalogResponse, error) {
		if req.Source == sbom.CatalogSourceHostDir {
			return &sbom.CatalogResponse{SyftJSON: json.RawMessage(hostJSON)}, nil
		}
		_, lerr := os.Stat(filepath.Join(req.Path, "oci-layout"))
		_, ierr := os.Stat(filepath.Join(req.Path, "index.json"))
		jobs <- seen{req: req, layout: lerr == nil, indexOK: ierr == nil}
		time.Sleep(5 * time.Millisecond)
		return &sbom.CatalogResponse{SyftJSON: json.RawMessage(imageJSON)}, nil
	})
	var offered atomic.Int32
	e.ctl.setAnswer(func(wire.Report) (int, wire.ReportResponse) {
		resp := wire.ReportResponse{Applied: true, Config: wire.AgentConfig{ReportIntervalSeconds: 3600, ImageListIntervalSeconds: 600}}
		if offered.Add(1) == 1 {
			deadline := time.Now().Add(5 * time.Minute)
			for _, id := range []string{"w1", "w2", "w3"} {
				resp.Work = append(resp.Work, wire.WorkRequest{ID: id, Digest: e.config, Platform: platform, Deadline: deadline})
			}
		}
		return 200, resp
	})
	e.startCataloguer(t)
	e.run(t)
	require.Equal(t, wire.KindFull, e.ctl.next(t).Kind)

	j := <-jobs
	require.Equal(t, sbom.CatalogSourceOCIDir, j.req.Source)
	require.Equal(t, platform, j.req.Platform)
	require.Equal(t, filepath.Join(resolvedScratch(t, e), "work-w1"), j.req.Path)
	require.True(t, j.layout && j.indexOK, "the OCI layout is staged when the cataloguer runs")
	require.Equal(t, int64(1<<30), j.req.MaxBytes)
	require.Positive(t, j.req.TimeoutSeconds)

	res := e.ctl.nextSBOM(t)
	require.Equal(t, "w1", res.ID)
	require.Equal(t, "worker-1", res.Node)
	require.Equal(t, version.Version, res.AgentVersion)
	require.Equal(t, e.config, res.Digest)
	require.JSONEq(t, imageJSON, string(res.SyftJSON))
	require.Empty(t, res.Unavailable)
	require.Empty(t, res.Failure)
	require.Equal(t, "w2", e.ctl.nextSBOM(t).ID)
	require.Equal(t, "w3", e.ctl.nextSBOM(t).ID)
	require.Equal(t, int32(1), e.runner.maxActive.Load(), "jobs run one at a time")
	require.Empty(t, workDirs(t, e.scratch), "every stage dir is removed")
}

func TestWork_UnavailableAndFailures(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.startCataloguer(t)
	a := newTestAgent(t, e)
	platform := "linux/" + runtime.GOARCH
	work := func(digest string) wire.WorkRequest {
		return wire.WorkRequest{ID: "w1", Digest: digest, Platform: platform, Deadline: time.Now().Add(5 * time.Minute)}
	}

	a.runJob(ctx, work("sha256:"+strings.Repeat("0", 64)))
	require.Equal(t, wire.UnavailableNotFound, e.ctl.nextSBOM(t).Unavailable)

	discarded := testImage(t, runtime.GOARCH)
	dm, _ := contentstoretest.WriteImage(t, e.storeDir(), discarded)
	layers, err := discarded.Layers()
	require.NoError(t, err)
	ld, err := layers[0].Digest()
	require.NoError(t, err)
	contentstoretest.RemoveBlob(t, e.storeDir(), ld.String())
	a.runJob(ctx, work(dm))
	res := e.ctl.nextSBOM(t)
	require.Equal(t, wire.UnavailableLayersDiscarded, res.Unavailable)
	require.Equal(t, dm, res.Digest)

	a.o.MaxImageBytes = 1
	a.runJob(ctx, work(e.manifest))
	require.Equal(t, wire.UnavailableTooLarge, e.ctl.nextSBOM(t).Unavailable)
	a.o.MaxImageBytes = 1 << 30

	for _, tc := range []struct {
		err                  *catalog.WorkError
		unavailable, failure string
	}{
		{&catalog.WorkError{Kind: sbom.KindTooLarge, Msg: "too big"}, wire.UnavailableTooLarge, ""},
		{&catalog.WorkError{Kind: sbom.KindFailed, Msg: "boom"}, "", "failed: boom"},
		{&catalog.WorkError{Kind: sbom.KindScratchFull, Msg: "image unpacked beyond the scratch limit"}, "",
			"scratch-full: image unpacked beyond the scratch limit"},
	} {
		e.runner.setFn(func(context.Context, sbom.CatalogRequest) (*sbom.CatalogResponse, error) { return nil, tc.err })
		a.runJob(ctx, work(e.manifest))
		res := e.ctl.nextSBOM(t)
		require.Equal(t, tc.unavailable, res.Unavailable, tc.err.Kind)
		require.Equal(t, tc.failure, res.Failure, tc.err.Kind)
		require.Empty(t, res.SyftJSON)
	}

	e.runner.setFn(func(context.Context, sbom.CatalogRequest) (*sbom.CatalogResponse, error) {
		return nil, &catalog.WorkError{Kind: sbom.KindBusy, Msg: "cataloguer is busy"}
	})
	a.runJob(ctx, work(e.manifest))
	e.ctl.noSBOM(t)

	calls := len(e.runner.requests())
	past := work(e.manifest)
	past.Deadline = time.Now().Add(-time.Second)
	a.runJob(ctx, past)
	e.ctl.noSBOM(t)
	require.Len(t, e.runner.requests(), calls, "work past its deadline is not started")

	require.Empty(t, workDirs(t, e.scratch))
	require.Equal(t, int32(1), e.runner.maxActive.Load())
}

func TestWork_UnsafeIDStaysInScratch(t *testing.T) {
	e := newEnv(t)
	a := newTestAgent(t, e)
	for _, id := range []string{"../../etc", "a/b", "..", ""} {
		dir := a.workDir(id)
		require.Equal(t, e.scratch, filepath.Dir(dir), id)
		require.True(t, strings.HasPrefix(filepath.Base(dir), "work-"), id)
	}
	require.Equal(t, filepath.Join(e.scratch, "work-w1"), a.workDir("w1"))
}

// debianImage is a linux/<arch> image whose layer holds a Debian 12 os-release and a dpkg status for libsideload1.
func debianImage(t *testing.T, arch string) v1.Image {
	t.Helper()
	files := []struct{ name, body string }{
		{"etc/os-release", "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\n" +
			"VERSION=\"12 (bookworm)\"\nVERSION_CODENAME=bookworm\nID=debian\n"},
		{"var/lib/dpkg/status", "Package: libsideload1\nStatus: install ok installed\nPriority: optional\nSection: libs\n" +
			"Installed-Size: 100\nMaintainer: Example <maintainer@example.org>\nArchitecture: " + arch + "\n" +
			"Source: sideload\nVersion: 1.2.3-1\nDescription: side-loaded fixture library\n\n"},
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range files {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: f.name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(f.body))}))
		_, err := io.WriteString(tw, f.body)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(buf.Bytes())), nil })
	require.NoError(t, err)
	img, err := mutate.AppendLayers(empty.Image, layer)
	require.NoError(t, err)
	cf, err := img.ConfigFile()
	require.NoError(t, err)
	cf = cf.DeepCopy()
	cf.OS, cf.Architecture = "linux", arch
	img, err = mutate.ConfigFile(img, cf)
	require.NoError(t, err)
	return mutate.ConfigMediaType(mutate.MediaType(img, types.OCIManifestSchema1), types.OCIConfigJSON)
}

func TestWork_RealSyftOnStagedLayout(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	t.Setenv("TMPDIR", t.TempDir())
	e.runner.setFn(func(rctx context.Context, req sbom.CatalogRequest) (*sbom.CatalogResponse, error) {
		return catalog.Catalog(rctx, req)
	})
	e.startCataloguer(t)
	a := newTestAgent(t, e)
	_, cfg := contentstoretest.WriteImage(t, e.storeDir(), debianImage(t, runtime.GOARCH))

	a.runJob(ctx, wire.WorkRequest{ID: "w1", Digest: cfg, Platform: "linux/" + runtime.GOARCH, Deadline: time.Now().Add(5 * time.Minute)})
	res := e.ctl.nextSBOM(t)
	require.Empty(t, res.Failure)
	require.Empty(t, res.Unavailable)
	doc, err := sbom.DecodeSyftJSON(res.SyftJSON)
	require.NoError(t, err)
	pkgs, _ := sbom.Normalize(cfg, doc)
	var names []string
	for _, p := range pkgs {
		names = append(names, p.Name)
		if p.Name == "libsideload1" {
			require.Equal(t, "deb", p.Ecosystem)
			require.Equal(t, "1.2.3-1", p.Version)
			require.NotNil(t, p.Distro)
			require.Equal(t, "debian", p.Distro.ID)
		}
	}
	require.Contains(t, names, "libsideload1")
	require.Empty(t, workDirs(t, e.scratch))
}
