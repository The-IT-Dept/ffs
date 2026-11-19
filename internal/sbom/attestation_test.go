package sbom

import (
	"context"
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	syftsbom "github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/registry"
	"github.com/the-it-dept/ffs/internal/registry/regtest"
)

var ctx = context.Background()

func fixtureSBOM(creator string) *syftsbom.SBOM {
	p := pkg.Package{
		Name:     "openssl",
		Version:  "3.0.15-1~deb12u1",
		Type:     pkg.DebPkg,
		PURL:     "pkg:deb/debian/openssl@3.0.15-1~deb12u1?arch=amd64&distro=debian-12&upstream=openssl",
		Metadata: pkg.DpkgDBEntry{Package: "openssl", Source: "openssl", Version: "3.0.15-1~deb12u1"},
	}
	p.SetID()
	return &syftsbom.SBOM{
		Artifacts: syftsbom.Artifacts{
			Packages:          pkg.NewCollection(p),
			LinuxDistribution: &linux.Release{ID: "debian", VersionID: "12", VersionCodename: "bookworm"},
		},
		Source:     source.Description{Name: "app", Metadata: source.ImageMetadata{UserInput: "app"}},
		Descriptor: syftsbom.Descriptor{Name: creator, Version: "1.57.2"},
	}
}

func encodeAs(t *testing.T, s *syftsbom.SBOM, kind string) []byte {
	t.Helper()
	var (
		b   []byte
		err error
	)
	switch kind {
	case "spdx":
		var enc syftsbom.FormatEncoder
		enc, err = spdxjson.NewFormatEncoderWithConfig(spdxjson.DefaultEncoderConfig())
		require.NoError(t, err)
		b, err = format.Encode(*s, enc)
	default:
		var enc syftsbom.FormatEncoder
		enc, err = cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
		require.NoError(t, err)
		b, err = format.Encode(*s, enc)
	}
	require.NoError(t, err)
	return b
}

func statementBytes(predType, subjectHex string, predicate []byte) []byte {
	return []byte(`{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"name":"app","digest":{"sha256":"` + subjectHex +
		`"}}],"predicateType":"` + predType + `","predicate":` + string(predicate) + `}`)
}

func hexOf(digest string) string { return strings.TrimPrefix(digest, "sha256:") }

func platformImage(t *testing.T, user string) v1.Image {
	t.Helper()
	img, err := random.Image(256, 1)
	require.NoError(t, err)
	cf, err := img.ConfigFile()
	require.NoError(t, err)
	cf = cf.DeepCopy()
	cf.OS, cf.Architecture = "linux", "amd64"
	cf.Config.User = user
	img, err = mutate.ConfigFile(img, cf)
	require.NoError(t, err)
	return img
}

// artifact builds an OCI artifact manifest with one layer, optionally referring to subject.
func artifact(t *testing.T, artifactType string, mt types.MediaType, data []byte, subject *v1.Descriptor) v1.Image {
	t.Helper()
	img, err := mutate.Append(mutate.MediaType(empty.Image, types.OCIManifestSchema1), mutate.Addendum{Layer: static.NewLayer(data, mt)})
	require.NoError(t, err)
	img = mutate.ConfigMediaType(img, types.MediaType(artifactType))
	if subject != nil {
		img = mutate.Subject(img, *subject).(v1.Image)
	}
	return img
}

func descriptorOf(t *testing.T, img v1.Image, digest string) *v1.Descriptor {
	t.Helper()
	mt, err := img.MediaType()
	require.NoError(t, err)
	size, err := img.Size()
	require.NoError(t, err)
	h, err := v1.NewHash(digest)
	require.NoError(t, err)
	return &v1.Descriptor{MediaType: mt, Size: size, Digest: h}
}

func spdxStatement(t *testing.T, creator, subjectHex string) []byte {
	t.Helper()
	return statementBytes("https://spdx.dev/Document", subjectHex, encodeAs(t, fixtureSBOM(creator), "spdx"))
}

func newSource() *AttestationSource { return NewAttestationSource(registry.New(registry.Options{})) }

func requireOpenSSL(t *testing.T, res *Result) {
	t.Helper()
	require.Equal(t, "attestation", res.Source)
	require.Equal(t, []string{AttestationCoverageNote}, res.Coverage.Notes)
	sb, err := DecodeSyftJSON(res.SyftJSON)
	require.NoError(t, err)
	var found bool
	for p := range sb.Artifacts.Packages.Enumerate() {
		if p.Name != "openssl" {
			continue
		}
		found = true
		md, ok := p.Metadata.(pkg.DpkgDBEntry)
		require.True(t, ok, "metadata %T", p.Metadata)
		require.Equal(t, "openssl", md.Source)
	}
	require.True(t, found, "openssl package")
	require.NotNil(t, sb.Artifacts.LinuxDistribution)
	require.Equal(t, "debian", sb.Artifacts.LinuxDistribution.ID)
}

func TestAttestation_ReferrersAPI(t *testing.T) {
	s := regtest.Start(t, regtest.WithReferrers())
	img := platformImage(t, "65532")
	d := s.Push(t, "app:1", img)
	art := artifact(t, "application/spdx+json", types.MediaType("application/spdx+json"),
		encodeAs(t, fixtureSBOM("syft"), "spdx"), descriptorOf(t, img, d))
	s.Push(t, "app", art)

	res, err := newSource().Acquire(ctx, Request{Repo: s.Host + "/app", Digest: d})
	require.NoError(t, err)
	requireOpenSSL(t, res)
	require.Equal(t, "65532", res.ConfigUser)

	plain := platformImage(t, "")
	d2 := s.Push(t, "app:2", plain)
	art2 := artifact(t, "application/spdx+json", types.MediaType("application/spdx+json"),
		encodeAs(t, fixtureSBOM("syft"), "spdx"), descriptorOf(t, plain, d2))
	s.Push(t, "app", art2)
	res, err = newSource().Acquire(ctx, Request{Repo: s.Host + "/app", Digest: d2})
	require.NoError(t, err)
	require.Equal(t, "", res.ConfigUser)
}

func TestAttestation_BuildKitInIndex(t *testing.T) {
	s := regtest.Start(t)
	img := platformImage(t, "")
	d, err := img.Digest()
	require.NoError(t, err)
	att := artifact(t, "application/vnd.oci.image.config.v1+json", mtInToto, spdxStatement(t, "syft", hexOf(d.String())), nil)
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
	idx = mutate.Annotations(idx, map[string]string{registry.AnnotationVersion: "1.27.3"}).(v1.ImageIndex)
	idxDigest := s.PushIndex(t, "app:1", idx)

	res, err := newSource().Acquire(ctx, Request{Repo: s.Host + "/app", Digest: d.String(), IndexDigest: idxDigest})
	require.NoError(t, err)
	requireOpenSSL(t, res)
	require.Equal(t, "1.27.3", res.VersionAnnotation)
}

func TestAttestation_TagSchemaFallback(t *testing.T) {
	s := regtest.Start(t)
	img := platformImage(t, "")
	d := s.Push(t, "app:1", img)
	art := artifact(t, "application/spdx+json", types.MediaType("application/spdx+json"),
		encodeAs(t, fixtureSBOM("syft"), "spdx"), descriptorOf(t, img, d))
	idx := mutate.AppendManifests(mutate.IndexMediaType(empty.Index, types.OCIImageIndex),
		mutate.IndexAddendum{Add: art, Descriptor: v1.Descriptor{ArtifactType: "application/spdx+json"}})
	s.PushIndex(t, "app:sha256-"+hexOf(d), idx)

	res, err := newSource().Acquire(ctx, Request{Repo: s.Host + "/app", Digest: d})
	require.NoError(t, err)
	requireOpenSSL(t, res)
}

func TestAttestation_CosignAtt(t *testing.T) {
	s := regtest.Start(t)
	img := platformImage(t, "")
	d := s.Push(t, "app:1", img)
	cdx := statementBytes("https://cyclonedx.org/bom", hexOf(d), encodeAs(t, fixtureSBOM("syft"), "cyclonedx"))
	env := `{"payloadType":"application/vnd.in-toto+json","payload":"` + base64.StdEncoding.EncodeToString(cdx) + `","signatures":[]}`
	att := artifact(t, "application/vnd.oci.image.config.v1+json", mtDSSE, []byte(env), nil)
	s.Push(t, "app:sha256-"+hexOf(d)+".att", att)

	res, err := newSource().Acquire(ctx, Request{Repo: s.Host + "/app", Digest: d})
	require.NoError(t, err)
	requireOpenSSL(t, res)
}

func TestAttestation_NonSyftCreatorFallsThrough(t *testing.T) {
	s := regtest.Start(t, regtest.WithReferrers())
	img := platformImage(t, "")
	d := s.Push(t, "app:1", img)
	for _, kind := range []string{"spdx", "cyclonedx"} {
		art := artifact(t, "application/spdx+json", types.MediaType("application/spdx+json"),
			encodeAs(t, fixtureSBOM("trivy"), kind), descriptorOf(t, img, d))
		s.Push(t, "app", art)
	}
	_, err := newSource().Acquire(ctx, Request{Repo: s.Host + "/app", Digest: d})
	require.ErrorIs(t, err, ErrNotFound)
}

func TestAttestation_SubjectMismatchIgnored(t *testing.T) {
	s := regtest.Start(t)
	img := platformImage(t, "")
	d := s.Push(t, "app:1", img)
	att := artifact(t, "application/vnd.oci.image.config.v1+json", mtInToto,
		spdxStatement(t, "syft", strings.Repeat("b", 64)), nil)
	s.Push(t, "app:sha256-"+hexOf(d)+".att", att)

	_, err := newSource().Acquire(ctx, Request{Repo: s.Host + "/app", Digest: d})
	require.ErrorIs(t, err, ErrNotFound)
}

func TestAttestation_NothingAttached(t *testing.T) {
	s := regtest.Start(t, regtest.WithReferrers())
	d := s.Push(t, "app:1", platformImage(t, ""))
	_, err := newSource().Acquire(ctx, Request{Repo: s.Host + "/app", Digest: d})
	require.ErrorIs(t, err, ErrNotFound)

	locked := regtest.Start(t, regtest.WithBasicAuth("u", "p"))
	_, err = newSource().Acquire(ctx, Request{Repo: locked.Host + "/app", Digest: d})
	require.ErrorIs(t, err, ErrNotFound)

	limited := regtest.Start(t, regtest.WithMiddleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if regexp.MustCompile(`/(referrers|manifests)/`).MatchString(r.URL.Path) {
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}))
	_, err = newSource().Acquire(ctx, Request{Repo: limited.Host + "/app", Digest: d})
	require.Equal(t, FailTransient, KindOf(err))
	require.NotErrorIs(t, err, ErrNotFound)

	cctx, cancel := context.WithCancel(ctx)
	cancel()
	_, err = newSource().Acquire(cctx, Request{Repo: s.Host + "/app", Digest: d})
	require.ErrorIs(t, err, context.Canceled)
}
