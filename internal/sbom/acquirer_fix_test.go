package sbom

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	syftsbom "github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/registry"
	"github.com/the-it-dept/ffs/internal/registry/regtest"
	"github.com/the-it-dept/ffs/internal/store"
)

// TestAcquirer_UnmatchedImageMatchedAgainAtStart (F7): an image whose match failed, or was cut short
// by a restart, is catalogued but has no matches; the next start runs the match again, and the
// image is no longer listed once a match completes.
func TestAcquirer_UnmatchedImageMatchedAgainAtStart(t *testing.T) {
	st, clock := acqStore(t), acqClock()
	old := onCataloguedDelay
	onCataloguedDelay = time.Millisecond
	t.Cleanup(func() { onCataloguedDelay = old })

	src := &fakeSource{name: "registry", res: &Result{SyftJSON: syftBytes(t, ""), Source: "registry"}}
	var failing atomic.Int32
	a := NewAcquirer(AcquirerOptions{Store: st, Sources: []Source{src}, Concurrency: 1, Now: clock.Now,
		OnCatalogued: func(context.Context, string) error { failing.Add(1); return errors.New("matcher failed") }})
	c, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { _ = a.Start(c); close(done) }()
	_, err := a.AcquireNow(ctx, acqReq())
	require.NoError(t, err)
	cancel()
	<-done
	require.EqualValues(t, onCataloguedTries, failing.Load())
	require.Equal(t, model.ImageCatalogued, getImg(t, st, acqDigest).Status)
	un, err := st.UnmatchedImages(ctx)
	require.NoError(t, err)
	require.Equal(t, []store.UnmatchedImage{{Digest: acqDigest, Attempts: 1}}, un)

	// A new process (the restart) matches it again without cataloguing it again.
	matched := make(chan string, 1)
	b := NewAcquirer(AcquirerOptions{Store: st, Sources: []Source{src}, Concurrency: 1, Now: clock.Now,
		OnCatalogued: func(_ context.Context, d string) error { matched <- d; return nil }})
	startAcq(t, b)
	select {
	case d := <-matched:
		require.Equal(t, acqDigest, d)
	case <-time.After(5 * time.Second):
		t.Fatal("the unmatched image was not matched again at start")
	}
	require.Eventually(t, func() bool {
		un, err := st.UnmatchedImages(ctx)
		return err == nil && len(un) == 0
	}, 5*time.Second, 5*time.Millisecond)
	require.EqualValues(t, 1, src.calls.Load())
}

// TestAcquirer_MatchGivenUpAfterLimit (F7): an image whose match keeps failing is quarantined rather
// than shown catalogued with no findings, or retried at every start.
func TestAcquirer_MatchGivenUpAfterLimit(t *testing.T) {
	st, clock := acqStore(t), acqClock()
	require.NoError(t, st.UpsertImage(ctx, model.Image{Digest: acqDigest, Status: model.ImageCatalogued}))
	require.NoError(t, st.MarkUnmatched(ctx, acqDigest, clock.Now()))
	for range matchAttemptLimit {
		_, err := st.BeginMatch(ctx, acqDigest)
		require.NoError(t, err)
	}
	var calls atomic.Int32
	a := NewAcquirer(AcquirerOptions{Store: st, Concurrency: 1, Now: clock.Now,
		OnCatalogued: func(context.Context, string) error { calls.Add(1); return nil }})
	startAcq(t, a)
	require.Eventually(t, func() bool {
		return getImgOrZero(st, acqDigest).Status == model.ImageCatalogFailed
	}, 5*time.Second, 5*time.Millisecond)
	img := getImg(t, st, acqDigest)
	require.Equal(t, reasonMatchFailed, img.StatusReason)
	require.True(t, img.QuarantinedUntil.Equal(clock.Now().Add(24*time.Hour)))
	require.Zero(t, calls.Load())
	un, err := st.UnmatchedImages(ctx)
	require.NoError(t, err)
	require.Empty(t, un)
}

// TestAcquirer_AttemptTheControllerDidNotSurviveCounts (F20): an acquisition still recorded as in
// progress at start means the process running it stopped (an out-of-memory kill while decoding a
// huge SBOM); it counts like a crash, so a second one quarantines the image instead of crash-looping.
func TestAcquirer_AttemptTheControllerDidNotSurviveCounts(t *testing.T) {
	st, clock := acqStore(t), acqClock()
	r := acqReq()
	src := &fakeSource{name: "registry", res: &Result{SyftJSON: syftBytes(t, ""), Source: "registry"}}

	// First death: recorded as one strike, then the attempt goes ahead.
	stale, err := st.BeginAcquire(ctx, r.Digest, clock.Now())
	require.NoError(t, err)
	require.False(t, stale)
	var seen model.Image
	src.script = func(context.Context, int, Request) (*Result, error) {
		seen = getImgOrZero(st, r.Digest)
		return nil, &AcquireError{Kind: FailTransient, Reason: "cataloguer busy"}
	}
	a := NewAcquirer(AcquirerOptions{Store: st, Sources: []Source{src}, Concurrency: 1, Now: clock.Now, RetryAfter: time.Hour})
	c, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { _ = a.Start(c); close(done) }()
	_, err = a.AcquireNow(ctx, r)
	require.Error(t, err)
	cancel()
	<-done
	require.Equal(t, 1, seen.Attempts)
	require.Equal(t, model.ImagePending, seen.Status)
	stale, err = st.BeginAcquire(ctx, r.Digest, clock.Now()) // the attempt ended: nothing left over
	require.NoError(t, err)
	require.False(t, stale)

	// Second death (the row just written is left over): quarantined without another attempt.
	calls := src.calls.Load()
	b := NewAcquirer(AcquirerOptions{Store: st, Sources: []Source{src}, Concurrency: 1, Now: clock.Now})
	startAcq(t, b)
	_, err = b.AcquireNow(ctx, r)
	require.Error(t, err)
	img := getImg(t, st, r.Digest)
	require.Equal(t, model.ImageCatalogFailed, img.Status)
	require.Equal(t, reasonControllerStopped, img.StatusReason)
	require.Equal(t, calls, src.calls.Load())
}

// TestAcquirer_SBOMTooLargeQuarantined (F20): an SBOM over the limit is never decoded in the
// controller; the image is quarantined.
func TestAcquirer_SBOMTooLargeQuarantined(t *testing.T) {
	st, clock := acqStore(t), acqClock()
	src := &fakeSource{name: "registry", res: &Result{SyftJSON: make([]byte, MaxSBOMBytes+1), Source: "registry"}}
	a := NewAcquirer(AcquirerOptions{Store: st, Sources: []Source{src}, Concurrency: 1, Now: clock.Now})
	startAcq(t, a)
	_, err := a.AcquireNow(ctx, acqReq())
	require.Error(t, err)
	img := getImg(t, st, acqDigest)
	require.Equal(t, model.ImageCatalogFailed, img.Status)
	require.Equal(t, fmt.Sprintf(reasonSBOMTooLarge, MaxSBOMBytes+1, MaxSBOMBytes), img.StatusReason)
}

// TestAcquirer_StoreErrorNotCounted (F13): a store write that fails says nothing about the image.
func TestAcquirer_StoreErrorNotCounted(t *testing.T) {
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "ffs.db"))
	require.NoError(t, err)
	clock := acqClock()
	src := &fakeSource{name: "registry"}
	src.script = func(context.Context, int, Request) (*Result, error) {
		require.NoError(t, st.Close()) // every write from here on fails
		return &Result{SyftJSON: syftBytes(t, ""), Source: "registry"}, nil
	}
	a := NewAcquirer(AcquirerOptions{Store: st, Sources: []Source{src}, Concurrency: 1, Now: clock.Now, RetryAfter: time.Hour})
	startAcq(t, a)
	_, err = a.AcquireNow(ctx, acqReq())
	require.Error(t, err)
	require.Equal(t, FailTransient, KindOf(err), err.Error())
	require.Zero(t, a.Stats().Failed)
}

func TestAcquirer_TransientBackoff(t *testing.T) {
	a := NewAcquirer(AcquirerOptions{RetryAfter: time.Minute})
	var got []time.Duration
	for range 7 {
		got = append(got, a.transientDelay(ctx, "d"))
	}
	require.Equal(t, []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute,
		30 * time.Minute, 30 * time.Minute}, got)
	a.resetTransient("d")
	require.Equal(t, time.Minute, a.transientDelay(ctx, "d"))
}

// TestAcquirer_StatsCountRetryWaits (R3): an image waiting out the delay before its next attempt is
// neither queued nor in flight, so Stats counts it as retrying until it is queued again; readiness
// must not take that gap for a finished catalogue.
func TestAcquirer_StatsCountRetryWaits(t *testing.T) {
	for _, tc := range []struct {
		name  string
		delay time.Duration
	}{{"waiting", time.Hour}, {"retried", 10 * time.Millisecond}} {
		t.Run(tc.name, func(t *testing.T) {
			st, clock := acqStore(t), acqClock()
			var calls atomic.Int32
			src := &fakeSource{name: "registry"}
			src.script = func(context.Context, int, Request) (*Result, error) {
				if calls.Add(1) == 1 {
					return nil, &AcquireError{Kind: FailTransient, Reason: "registry unavailable"}
				}
				return &Result{SyftJSON: syftBytes(t, ""), Source: "registry"}, nil
			}
			a := NewAcquirer(AcquirerOptions{Store: st, Sources: []Source{src}, Now: clock.Now, RetryAfter: tc.delay})
			startAcq(t, a)
			a.Enqueue(acqReq())
			if tc.delay == time.Hour {
				require.Eventually(t, func() bool {
					s := a.Stats()
					return calls.Load() == 1 && s.Queued == 0 && s.InFlight == 0 && s.Retrying == 1
				}, 5*time.Second, time.Millisecond, "neither queued nor in flight, but waiting to retry")
				return
			}
			require.Eventually(t, func() bool { return getImgOrZero(st, acqReq().Digest).Status == model.ImageCatalogued },
				5*time.Second, 5*time.Millisecond)
			require.Equal(t, 0, a.Stats().Retrying, "no longer waiting once queued again")
		})
	}
}

// TestAcquirer_CataloguerDeathRetriesOverlappingImageAlone (F14): when the catalog container dies with
// two jobs in flight, neither is counted; each runs again alone, so only the image that kills the
// cataloguer on its own is quarantined.
func TestAcquirer_CataloguerDeathRetriesOverlappingImageAlone(t *testing.T) {
	st, clock := acqStore(t), acqClock()
	const poison, victim = "sha256:poison", "sha256:victim"
	good := syftBytes(t, "")
	var (
		crashes atomic.Int32   // times the poison image took the cataloguer down
		arrived sync.WaitGroup // the first round: both jobs are in flight when the cataloguer dies
	)
	arrived.Add(2)
	stopped := &AcquireError{Kind: FailCounted, Reason: reasonStopped}
	src := &fakeSource{name: "registry"}
	src.script = func(ctx context.Context, n int, r Request) (*Result, error) {
		if n <= 2 {
			arrived.Done()
			arrived.Wait()
			return nil, stopped
		}
		before := crashes.Load()
		if r.Digest == poison {
			time.Sleep(20 * time.Millisecond)
			crashes.Add(1) // the whole catalog container goes down, with every job in it
			return nil, stopped
		}
		time.Sleep(60 * time.Millisecond)
		if crashes.Load() != before {
			return nil, stopped
		}
		return &Result{SyftJSON: good, Source: "registry"}, nil
	}
	a := NewAcquirer(AcquirerOptions{Store: st, Sources: []Source{src}, Concurrency: 2, Now: clock.Now, RetryAfter: 10 * time.Millisecond})
	startAcq(t, a)
	a.Enqueue(Request{Repo: "docker.io/library/x", Digest: poison, Platform: "linux/amd64"})
	a.Enqueue(Request{Repo: "docker.io/library/y", Digest: victim, Platform: "linux/amd64"})

	require.Eventually(t, func() bool {
		return getImgOrZero(st, victim).Status == model.ImageCatalogued && getImgOrZero(st, poison).Status == model.ImageCatalogFailed
	}, 10*time.Second, 5*time.Millisecond)
	require.Equal(t, 0, getImg(t, st, victim).Attempts)
	require.Equal(t, reasonStopped, getImg(t, st, poison).StatusReason)
}

// TestAcquirer_OtherOwnersCredentialsTried (F18): a pull refused with the first owner's credentials
// is tried with another owner's before the image is marked unresolvable.
func TestAcquirer_OtherOwnersCredentialsTried(t *testing.T) {
	st, clock := acqStore(t), acqClock()
	r := acqReq()
	r.Creds = registry.CredSet{Namespace: "apps-old", ServiceAccount: "default", PullSecrets: []string{"expired"}}
	for _, o := range []model.Owner{
		{Ref: model.OwnerRef{Kind: "Deployment", Namespace: "apps-old", Name: "web"}, ServiceAccount: "default",
			PullSecrets: []string{"expired"}, Containers: []model.ContainerUse{{Name: "app", Digest: r.Digest}}},
		{Ref: model.OwnerRef{Kind: "Deployment", Namespace: "prod", Name: "web"}, ServiceAccount: "web",
			PullSecrets: []string{"regcred"}, Containers: []model.ContainerUse{{Name: "app", Digest: r.Digest}}},
	} {
		require.NoError(t, st.UpsertOwner(ctx, o))
	}
	var tried []string
	src := &fakeSource{name: "registry"}
	src.script = func(_ context.Context, _ int, req Request) (*Result, error) {
		tried = append(tried, req.Creds.Key())
		if req.Creds.Namespace != "prod" {
			return nil, &AcquireError{Kind: FailUnresolvable, Reason: fmt.Sprintf(registry.ReasonUnauthorized, req.Repo)}
		}
		return &Result{SyftJSON: syftBytes(t, ""), Source: "registry"}, nil
	}
	a := NewAcquirer(AcquirerOptions{Store: st, Sources: []Source{src}, Concurrency: 1, Now: clock.Now})
	startAcq(t, a)
	_, err := a.AcquireNow(ctx, r)
	require.NoError(t, err)
	require.Equal(t, model.ImageCatalogued, getImg(t, st, r.Digest).Status)
	require.Equal(t, []string{"apps-old|default|expired", "prod|web|regcred"}, tried)
}

// TestAcquirer_LowPriorityAndJobDeadline (F19, F4): sources run under registry.LowPriority, and a
// source that never returns is cut off by the job deadline without counting against the image.
func TestAcquirer_LowPriorityAndJobDeadline(t *testing.T) {
	st, clock := acqStore(t), acqClock()
	var low atomic.Bool
	src := &fakeSource{name: "registry"}
	src.script = func(ctx context.Context, n int, _ Request) (*Result, error) {
		low.Store(registry.IsLowPriority(ctx))
		<-ctx.Done() // a registry that never answers
		return nil, ctx.Err()
	}
	a := NewAcquirer(AcquirerOptions{Store: st, Sources: []Source{src}, Concurrency: 1, Now: clock.Now,
		JobTimeout: 50 * time.Millisecond, RetryAfter: time.Hour})
	startAcq(t, a)
	done := make(chan error, 1)
	go func() { _, err := a.AcquireNow(ctx, acqReq()); done <- err }()
	select {
	case err := <-done:
		require.Equal(t, FailTransient, KindOf(err), err.Error())
	case <-time.After(5 * time.Second):
		t.Fatal("the acquisition is still waiting on a source that never returns")
	}
	require.True(t, low.Load())
	require.Zero(t, getImgOrZero(st, acqDigest).Attempts)
	require.Zero(t, a.Stats().Failed)
}

// phpSBOM is an image SBOM with php built from source, found only by Syft's binary classifier, and
// the Debian packages under it.
func phpSBOM() *syftsbom.SBOM {
	doc := fixtureSBOM("syft")
	php := pkg.Package{Name: "php-cli", Version: "8.3.14", Type: pkg.BinaryPkg, PURL: "pkg:generic/php@8.3.14",
		Metadata: pkg.BinarySignature{Matches: []pkg.ClassifierMatch{{Classifier: "php-cli-binary"}}}}
	php.SetID()
	doc.Artifacts.Packages.Add(php)
	doc.Artifacts.LinuxDistribution = &linux.Release{ID: "debian", VersionID: "12", VersionCodename: "bookworm"}
	return doc
}

// TestAttestationFormatsLoseClassifier is the evidence behind cataloguing every image (F8): php
// found by a binary classifier comes back from Syft's SPDX and CycloneDX decoders without its
// classifier, which the upstream-runtime fast path needs.
func TestAttestationFormatsLoseClassifier(t *testing.T) {
	for _, kind := range []string{"spdx", "cyclonedx"} {
		sb := newSource().accept(acqReq(), encodeAs(t, phpSBOM(), kind), nil)
		require.NotNil(t, sb, kind)
		b, err := EncodeSyftJSON(sb)
		require.NoError(t, err)
		doc, err := DecodeSyftJSON(b)
		require.NoError(t, err)
		pkgs, _ := Normalize(acqDigest, doc)
		for _, p := range pkgs {
			if p.Name == "php-cli" {
				require.Empty(t, p.Classifier, kind)
			}
		}
	}
}

// TestAcquirer_CatalogFirstKeepsClassifier (F8): with the cataloguer first and the attestation only
// as the fallback, an attested php image keeps the classifier the upstream-runtime map keys on.
func TestAcquirer_CatalogFirstKeepsClassifier(t *testing.T) {
	st, clock := acqStore(t), acqClock()
	catalogued, err := EncodeSyftJSON(phpSBOM())
	require.NoError(t, err)
	cat := &fakeSource{name: "registry", res: &Result{SyftJSON: catalogued, Source: "registry"}}
	att := &fakeSource{name: "attestation", err: errors.New("must not be called")}
	a := NewAcquirer(AcquirerOptions{Store: st, Sources: []Source{cat}, Fallback: att, Concurrency: 1, Now: clock.Now})
	startAcq(t, a)
	_, err = a.AcquireNow(ctx, acqReq())
	require.NoError(t, err)
	require.Zero(t, att.calls.Load())
	pkgs, err := st.PackagesForImage(ctx, acqDigest)
	require.NoError(t, err)
	var php *model.Package
	for i := range pkgs {
		if pkgs[i].Name == "php-cli" {
			php = &pkgs[i]
		}
	}
	require.NotNil(t, php)
	require.Equal(t, "binary", php.Ecosystem)
	require.Equal(t, "php-cli-binary", php.Classifier)
}

// TestAcquirer_AttestationFallbackForTooLarge (F8): an image the cataloguer refuses as too large takes
// its attested SBOM rather than none; without one it is quarantined as before.
func TestAcquirer_AttestationFallbackForTooLarge(t *testing.T) {
	st, clock := acqStore(t), acqClock()
	cat := &fakeSource{name: "registry", err: &AcquireError{Kind: FailQuarantine, Reason: "compressed layers total 12 GiB"}}
	att := &fakeSource{name: "attestation", res: &Result{SyftJSON: syftBytes(t, ""), Source: "attestation",
		Coverage: model.Coverage{Notes: []string{AttestationCoverageNote}}}}
	a := NewAcquirer(AcquirerOptions{Store: st, Sources: []Source{cat}, Fallback: att, Concurrency: 1, Now: clock.Now})
	startAcq(t, a)
	_, err := a.AcquireNow(ctx, acqReq())
	require.NoError(t, err)
	img := getImg(t, st, acqDigest)
	require.Equal(t, model.ImageCatalogued, img.Status)
	require.Equal(t, "attestation", img.Source)
	require.Contains(t, img.Coverage.Notes, AttestationCoverageNote)

	const other = "sha256:other"
	att.res, att.err = nil, ErrNotFound
	_, err = a.AcquireNow(ctx, Request{Repo: "docker.io/library/x", Digest: other, Platform: "linux/amd64"})
	require.Error(t, err)
	require.Equal(t, model.ImageCatalogFailed, getImg(t, st, other).Status)
}

// TestDefaultSources_AttestedPHPImageKeepsClassifier (F8) is the golden case of spec §1 and §6.5: a
// php image built with BuildKit carries a Syft SPDX attestation in its index. With ffs's sources the
// image is still catalogued, so php keeps the classifier the upstream-runtime map keys on.
func TestDefaultSources_AttestedPHPImageKeepsClassifier(t *testing.T) {
	s := regtest.Start(t)
	img := platformImage(t, "")
	d, err := img.Digest()
	require.NoError(t, err)
	spdx := statementBytes("https://spdx.dev/Document", hexOf(d.String()), encodeAs(t, phpSBOM(), "spdx"))
	att := artifact(t, "application/vnd.oci.image.config.v1+json", mtInToto, spdx, nil)
	linuxAmd64, err := v1.ParsePlatform("linux/amd64")
	require.NoError(t, err)
	idx := mutate.AppendManifests(mutate.IndexMediaType(empty.Index, types.OCIImageIndex),
		mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{Platform: linuxAmd64}},
		mutate.IndexAddendum{Add: att, Descriptor: v1.Descriptor{
			Platform: &v1.Platform{OS: "unknown", Architecture: "unknown"},
			Annotations: map[string]string{
				"vnd.docker.reference.type":   "attestation-manifest",
				"vnd.docker.reference.digest": d.String(),
			},
		}})
	idxDigest := s.PushIndex(t, "php:8.3-fpm", idx)
	r := Request{Repo: s.Host + "/php", Digest: d.String(), IndexDigest: idxDigest, Platform: "linux/amd64"}

	reg := registry.New(registry.Options{})
	fake := startFakeCatalog(t, &countingRegistry{Client: reg})
	catalogued, err := EncodeSyftJSON(phpSBOM())
	require.NoError(t, err)
	fake.set(http.StatusOK, CatalogResponse{SyftJSON: catalogued}, false)
	cfg := config.Default().Catalog
	cfg.Socket = fake.socket

	st, clock := acqStore(t), acqClock()
	sources, fallback := DefaultSources(reg, cfg)
	a := NewAcquirer(AcquirerOptions{Store: st, Sources: sources, Fallback: fallback, Concurrency: 1, Now: clock.Now})
	startAcq(t, a)
	_, err = a.AcquireNow(ctx, r)
	require.NoError(t, err)

	pkgs, err := st.PackagesForImage(ctx, r.Digest)
	require.NoError(t, err)
	var php *model.Package
	for i := range pkgs {
		if pkgs[i].Name == "php-cli" {
			php = &pkgs[i]
		}
	}
	require.NotNil(t, php, "php catalogued")
	require.Equal(t, "binary", php.Ecosystem)
	require.Equal(t, "php-cli-binary", php.Classifier)
	require.Equal(t, "registry", getImg(t, st, r.Digest).Source)
}

// TestAttestation_NoOSInventoryNotAccepted (F8): an SBOM without an OS package inventory, such as a
// scan of the source directory attested to the image, is not taken as the image's inventory.
func TestAttestation_NoOSInventoryNotAccepted(t *testing.T) {
	s := regtest.Start(t)
	img := platformImage(t, "")
	d := s.Push(t, "app:1", img)
	dir := fixtureSBOM("syft")
	mod := pkg.Package{Name: "github.com/example/app", Version: "v1.2.3", Type: pkg.GoModulePkg,
		PURL: "pkg:golang/github.com/example/app@v1.2.3"}
	mod.SetID()
	dir.Artifacts.Packages = pkg.NewCollection(mod) // the repository's go.mod, no OS packages
	dir.Artifacts.LinuxDistribution = nil
	dir.Source = source.Description{Name: "app", Metadata: source.DirectoryMetadata{Path: "."}}
	att := artifact(t, "application/vnd.oci.image.config.v1+json", mtInToto,
		statementBytes("https://spdx.dev/Document", hexOf(d), encodeAs(t, dir, "spdx")), nil)
	s.Push(t, "app:sha256-"+hexOf(d)+".att", att)

	_, err := newSource().Acquire(ctx, Request{Repo: s.Host + "/app", Digest: d})
	require.ErrorIs(t, err, ErrNotFound)
}

// TestAttestation_TagLookupsHeadFirst (F19): the sha256-<hex> and .att tag lookups ask with HEAD,
// which costs no manifest budget, and GET only a tag that exists.
func TestAttestation_TagLookupsHeadFirst(t *testing.T) {
	s := regtest.Start(t)
	d := s.Push(t, "app:1", platformImage(t, ""))
	_, err := newSource().Acquire(ctx, Request{Repo: s.Host + "/app", Digest: d})
	require.ErrorIs(t, err, ErrNotFound)
	tagRe := regexp.MustCompile(`/manifests/sha256-`)
	require.Zero(t, s.Count(http.MethodGet, tagRe))
	require.Equal(t, 2, s.Count(http.MethodHead, tagRe))
}

// TestAcquirer_RefusedRequestUnresolvable (F53): a request the cataloguer refuses as invalid can never
// succeed as it is: the image is unresolvable (retried after UnresolvableRetry) at once, no strike is
// counted, and other owners' credentials are not tried, since they would not change the answer.
func TestAcquirer_RefusedRequestUnresolvable(t *testing.T) {
	st, clock := acqStore(t), acqClock()
	r := acqReq()
	require.NoError(t, st.UpsertOwner(ctx, model.Owner{Ref: model.OwnerRef{Kind: "Deployment", Namespace: "prod", Name: "web"},
		ServiceAccount: "web", Containers: []model.ContainerUse{{Name: "app", Digest: r.Digest}}}))
	src := &fakeSource{name: "registry", err: (&CatalogSource{}).statusError(r, http.StatusBadRequest,
		CatalogError{Kind: KindBadRequest, Error: "unknown platform"})}
	a := NewAcquirer(AcquirerOptions{Store: st, Sources: []Source{src}, Concurrency: 1, Now: clock.Now})
	startAcq(t, a)
	_, err := a.AcquireNow(ctx, r)
	require.Error(t, err)
	require.Equal(t, int32(1), src.calls.Load(), "no other credentials tried")
	img := getImg(t, st, r.Digest)
	require.Equal(t, model.ImageUnresolvable, img.Status)
	require.Equal(t, "cataloguer rejected the request: unknown platform", img.StatusReason)
	require.Zero(t, img.Attempts)
	require.True(t, img.QuarantinedUntil.Equal(clock.Now().Add(defaultUnresolvableRetry)), img.QuarantinedUntil)
}

// TestAcquirer_StopAnswersQueuedWaiters (F53): AcquireNow callers whose job is still queued when the
// acquirer stops get ErrStopped rather than waiting until their own context ends, and a request after
// the stop is answered at once.
func TestAcquirer_StopAnswersQueuedWaiters(t *testing.T) {
	st, clock := acqStore(t), acqClock()
	started, release := make(chan struct{}), make(chan struct{})
	src := &fakeSource{name: "registry"}
	src.script = func(context.Context, int, Request) (*Result, error) {
		close(started)
		<-release
		return &Result{SyftJSON: syftBytes(t, ""), Source: "registry"}, nil
	}
	a := NewAcquirer(AcquirerOptions{Store: st, Sources: []Source{src}, Concurrency: 1, Now: clock.Now})
	sctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { _ = a.Start(sctx); close(done) }()

	a.Enqueue(Request{Repo: "docker.io/library/x", Digest: "sha256:running", Platform: "linux/amd64"})
	<-started
	queued := make(chan error, 1)
	go func() {
		_, err := a.AcquireNow(ctx, Request{Repo: "docker.io/library/y", Digest: "sha256:queued", Platform: "linux/amd64"})
		queued <- err
	}()
	require.Eventually(t, func() bool { return a.Stats().Queued == 1 }, 5*time.Second, time.Millisecond)

	cancel()
	select {
	case err := <-queued:
		require.ErrorIs(t, err, ErrStopped)
	case <-time.After(5 * time.Second):
		t.Fatal("a queued AcquireNow was not answered when the acquirer stopped")
	}
	close(release)
	<-done
	require.Zero(t, a.Stats().Queued)
	_, err := a.AcquireNow(ctx, acqReq())
	require.ErrorIs(t, err, ErrStopped)
}

// TestAcquirer_ScratchFull (F81): an image that fills the cataloguer's scratch space on its own is
// quarantined at once, not downloaded again; one that filled it while another job ran is retried
// alone first, since either job may have filled the shared space.
func TestAcquirer_ScratchFull(t *testing.T) {
	full := (&CatalogSource{}).statusError(acqReq(), http.StatusInsufficientStorage,
		CatalogError{Kind: KindScratchFull, Error: "image unpacked beyond the scratch limit"})

	t.Run("alone", func(t *testing.T) {
		st, clock := acqStore(t), acqClock()
		src := &fakeSource{name: "registry", err: full}
		a := NewAcquirer(AcquirerOptions{Store: st, Sources: []Source{src}, Concurrency: 1, Now: clock.Now,
			RetryAfter: 10 * time.Millisecond})
		startAcq(t, a)
		_, err := a.AcquireNow(ctx, acqReq())
		require.Error(t, err)
		img := getImg(t, st, acqDigest)
		require.Equal(t, model.ImageCatalogFailed, img.Status)
		require.Equal(t, reasonScratchFull, img.StatusReason)
		require.True(t, img.QuarantinedUntil.Equal(clock.Now().Add(defaultQuarantineFor)))
		time.Sleep(50 * time.Millisecond)
		require.Equal(t, int32(1), src.calls.Load(), "not downloaded again")
	})

	t.Run("overlapping", func(t *testing.T) {
		st, clock := acqStore(t), acqClock()
		const big, small = "sha256:big", "sha256:small"
		var bigCalls atomic.Int32
		smallIn := make(chan struct{})
		src := &fakeSource{name: "registry"}
		src.script = func(_ context.Context, _ int, r Request) (*Result, error) {
			if r.Digest == big {
				if bigCalls.Add(1) == 1 {
					<-smallIn // both jobs are in flight
				}
				return nil, full
			}
			close(smallIn)
			time.Sleep(30 * time.Millisecond)
			return &Result{SyftJSON: syftBytes(t, ""), Source: "registry"}, nil
		}
		a := NewAcquirer(AcquirerOptions{Store: st, Sources: []Source{src}, Concurrency: 2, Now: clock.Now,
			RetryAfter: 10 * time.Millisecond})
		startAcq(t, a)
		a.Enqueue(Request{Repo: "docker.io/library/big", Digest: big, Platform: "linux/amd64"})
		a.Enqueue(Request{Repo: "docker.io/library/small", Digest: small, Platform: "linux/amd64"})

		require.Eventually(t, func() bool {
			return getImgOrZero(st, big).Status == model.ImageCatalogFailed && getImgOrZero(st, small).Status == model.ImageCatalogued
		}, 10*time.Second, 5*time.Millisecond)
		require.Equal(t, int32(2), bigCalls.Load(), "retried once, alone")
		require.Equal(t, reasonScratchFull, getImg(t, st, big).StatusReason)
	})
}
