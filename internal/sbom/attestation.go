package sbom

import (
	"bytes"
	"context"
	"errors"
	"strings"

	"github.com/anchore/syft/syft/format"
	syftsbom "github.com/anchore/syft/syft/sbom"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/registry"
)

// AttestationCoverageNote is recorded on every SBOM taken from an attestation.
const AttestationCoverageNote = "inventory from a build attestation; executables not attributed to a package were not measured"

const (
	attestationSource = "attestation"
	// maxCandidates bounds the manifests fetched per lookup step.
	maxCandidates = 8

	referenceDigestAnnotation = "vnd.docker.reference.digest"
	referenceTypeAnnotation   = "vnd.docker.reference.type"
	attestationManifestType   = "attestation-manifest"
)

// AttestationSource takes an SBOM from a build attestation attached to the image. It is used as
// the primary input only when the SBOM's creator is Syft (BuildKit's scanner and syft-generated
// cosign attestations); anything else is ErrNotFound so the cataloguer runs.
type AttestationSource struct {
	reg *registry.Client
}

// NewAttestationSource returns a source reading attestations through reg.
func NewAttestationSource(reg *registry.Client) *AttestationSource {
	return &AttestationSource{reg: reg}
}

// Name is the Source name recorded on results.
func (s *AttestationSource) Name() string { return attestationSource }

// artifactTypes are the referrer artifact types worth fetching.
var artifactTypes = map[string]bool{
	"":          true,
	mtSPDX:      true,
	mtCycloneDX: true,
	mtInToto:    true,
	mtDSSE:      true,
	mtBundle:    true,
}

// Acquire looks, in order, at the referrers API, the BuildKit attestation manifest in the image
// index, the referrers tag schema (sha256-<hex>) and the cosign .att tag, and stops at the first
// accepted SBOM.
func (s *AttestationSource) Acquire(ctx context.Context, r Request) (*Result, error) {
	hex := strings.TrimPrefix(r.Digest, "sha256:")
	var version string

	steps := []func() ([]string, error){
		func() ([]string, error) {
			descs, err := s.reg.Referrers(ctx, r.Repo, r.Digest, r.Creds)
			return artifactDigests(descs), err
		},
		func() ([]string, error) {
			if r.IndexDigest == "" {
				return nil, nil
			}
			d, err := s.reg.Get(ctx, r.Repo+"@"+r.IndexDigest, r.Creds)
			if err != nil {
				return nil, err
			}
			idx, err := d.ImageIndex()
			if err != nil {
				return nil, err
			}
			im, err := idx.IndexManifest()
			if err != nil {
				return nil, err
			}
			version = im.Annotations[registry.AnnotationVersion]
			var out []string
			for _, m := range im.Manifests {
				if m.Annotations[referenceTypeAnnotation] == attestationManifestType && m.Annotations[referenceDigestAnnotation] == r.Digest {
					out = append(out, m.Digest.String())
				}
			}
			return out, nil
		},
		func() ([]string, error) {
			d, err := s.reg.Get(ctx, r.Repo+":sha256-"+hex, r.Creds)
			if err != nil {
				return nil, err
			}
			if !d.MediaType.IsIndex() {
				return nil, nil
			}
			idx, err := d.ImageIndex()
			if err != nil {
				return nil, err
			}
			im, err := idx.IndexManifest()
			if err != nil {
				return nil, err
			}
			return artifactDigests(im.Manifests), nil
		},
	}
	for _, step := range steps {
		digests, err := step()
		if err := soften(ctx, err); err != nil {
			return nil, err
		}
		for _, d := range digests {
			img, err := s.image(ctx, r, r.Repo+"@"+d)
			if err := soften(ctx, err); err != nil {
				return nil, err
			}
			if res, err := s.fromImage(ctx, r, img, version); res != nil || err != nil {
				return res, err
			}
		}
	}

	img, err := s.image(ctx, r, r.Repo+":sha256-"+hex+".att")
	if err := soften(ctx, err); err != nil {
		return nil, err
	}
	if res, err := s.fromImage(ctx, r, img, version); res != nil || err != nil {
		return res, err
	}
	return nil, ErrNotFound
}

// artifactDigests returns the digests of image manifests that may hold an SBOM.
func artifactDigests(descs []v1.Descriptor) []string {
	var out []string
	for _, d := range descs {
		if d.MediaType != types.OCIManifestSchema1 && d.MediaType != types.DockerManifestSchema2 {
			continue
		}
		if !artifactTypes[d.ArtifactType] {
			continue
		}
		if len(out) == maxCandidates {
			break
		}
		out = append(out, d.Digest.String())
	}
	return out
}

// image fetches the image at ref; a nil image with a nil error means ref is not an image manifest.
func (s *AttestationSource) image(ctx context.Context, r Request, ref string) (v1.Image, error) {
	d, err := s.reg.Get(ctx, ref, r.Creds)
	if err != nil {
		return nil, err
	}
	if d.MediaType.IsIndex() {
		return nil, nil
	}
	return d.Image()
}

// fromImage tries each layer of an attestation image. It returns (nil, nil) when none is usable.
func (s *AttestationSource) fromImage(ctx context.Context, r Request, img v1.Image, version string) (*Result, error) {
	if img == nil {
		return nil, nil
	}
	layers, err := img.Layers()
	if err := soften(ctx, registry.Classify(err)); err != nil {
		return nil, err
	}
	for _, l := range layers {
		mt, err := l.MediaType()
		if err != nil {
			continue
		}
		rc, err := l.Compressed()
		if err := soften(ctx, registry.Classify(err)); err != nil {
			return nil, err
		}
		if err != nil {
			continue
		}
		_, predicate, subjects, err := statementFromLayer(string(mt), rc)
		_ = rc.Close()
		if err := soften(ctx, registry.Classify(err)); err != nil {
			return nil, err
		}
		if err != nil {
			continue
		}
		sb := s.accept(r, predicate, subjects)
		if sb == nil {
			continue
		}
		return s.result(ctx, r, sb, version)
	}
	return nil, nil
}

// accept decodes predicate and returns it when it covers r.Digest, was made by Syft and lists packages.
func (s *AttestationSource) accept(r Request, predicate []byte, subjects []string) *syftsbom.SBOM {
	if len(subjects) > 0 {
		hex := strings.TrimPrefix(r.Digest, "sha256:")
		found := false
		for _, sub := range subjects {
			found = found || sub == hex
		}
		if !found {
			return nil
		}
	}
	if !creatorIsSyft(predicate) {
		return nil
	}
	sb, _, _, err := format.Decode(bytes.NewReader(predicate))
	if err != nil || sb == nil || sb.Artifacts.Packages.PackageCount() == 0 {
		return nil
	}
	return sb
}

func (s *AttestationSource) result(ctx context.Context, r Request, sb *syftsbom.SBOM, version string) (*Result, error) {
	img, err := s.reg.Image(ctx, r.Repo, r.Digest, r.Creds)
	var cfg *v1.ConfigFile
	if err == nil {
		cfg, err = img.ConfigFile()
		err = registry.Classify(err)
	}
	if err := soften(ctx, err); err != nil {
		return nil, err
	}
	if err != nil || cfg == nil {
		return nil, ErrNotFound
	}
	b, err := EncodeSyftJSON(sb)
	if err != nil {
		return nil, err
	}
	return &Result{
		SyftJSON:          b,
		Source:            attestationSource,
		VersionAnnotation: version,
		ConfigUser:        cfg.Config.User,
		Coverage:          model.Coverage{Notes: []string{AttestationCoverageNote}},
	}, nil
}

// soften maps a registry error to the Acquire contract: context errors pass through, rate
// limiting is transient, and anything else means "no attestation here" (nil, so the caller moves on).
func soften(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if cerr := ctx.Err(); cerr != nil {
		return cerr
	}
	if errors.Is(err, registry.ErrRateLimited) {
		return &AcquireError{Kind: FailTransient, Err: err}
	}
	return nil
}
