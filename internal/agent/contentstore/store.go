// Package contentstore reads containerd's content store as plain files: it lists the image manifests and indexes
// a node holds and stages one image as an OCI layout for the cataloguer. It never imports containerd.
package contentstore

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/the-it-dept/ffs/internal/agentapi/wire"
)

// MaxManifestBytes bounds the blobs Scan reads: larger blobs are never read.
const MaxManifestBytes = 4 << 20

// maxIndexDepth bounds how deep Resolve and Scan follow nested indexes.
const maxIndexDepth = 2

// Errors Resolve and Stage return, wrapped with detail.
var (
	ErrNotFound        = errors.New("contentstore: digest not in the content store")
	ErrLayersDiscarded = errors.New("contentstore: layers discarded")
	ErrTooLarge        = errors.New("contentstore: image larger than the limit")
	// ErrScratch is a failure to write the staged layout (ENOSPC, EACCES, EROFS…): the collector's scratch
	// volume, not the image, is at fault.
	ErrScratch = errors.New("contentstore: writing the staged layout")
)

type blobKind int

const (
	kindOther blobKind = iota
	kindManifest
	kindIndex
	kindConfig
)

// blobInfo is the cached classification of one blob. Blobs are immutable, so it never changes.
type blobInfo struct {
	kind     blobKind
	manifest *v1.Manifest
	index    *v1.IndexManifest
	platform string // image config: "os/arch[/variant]"
}

// BuildKit marks the attestation manifests it adds to an image index with this annotation and an
// unknown/unknown platform.
const (
	refTypeAnnotation  = "vnd.docker.reference.type"
	refTypeAttestation = "attestation-manifest"
)

// Store reads one containerd content store. It is not safe for concurrent use.
type Store struct {
	dir       string
	blobs     map[string]*blobInfo // by digest; pruned to the digests the latest Scan listed
	attest    map[string]bool      // manifests an index names as attestations, as of the latest refresh
	fullReads int                  // blobs read in full (tests)
}

// Open returns a Store over dir, a containerd ".../io.containerd.content.v1.content" directory. It reads nothing.
func Open(dir string) *Store {
	return &Store{dir: dir, blobs: map[string]*blobInfo{}, attest: map[string]bool{}}
}

func (s *Store) blobPath(digest string) string {
	return filepath.Join(s.dir, "blobs", "sha256", strings.TrimPrefix(digest, "sha256:"))
}

// refresh lists the blobs dir, classifies blobs it has not seen and drops blobs that are gone.
func (s *Store) refresh(ctx context.Context) error {
	entries, err := os.ReadDir(filepath.Join(s.dir, "blobs", "sha256"))
	if err != nil {
		return fmt.Errorf("reading the content store: %w", err)
	}
	listed := make(map[string]bool, len(entries))
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !isHex64(e.Name()) || !e.Type().IsRegular() {
			continue
		}
		digest := "sha256:" + e.Name()
		listed[digest] = true
		if _, ok := s.blobs[digest]; ok {
			continue
		}
		info, err := s.classify(digest)
		if errors.Is(err, fs.ErrNotExist) {
			delete(listed, digest) // removed since the listing
			continue
		}
		if err != nil {
			return err
		}
		s.blobs[digest] = info
	}
	for d := range s.blobs {
		if !listed[d] {
			delete(s.blobs, d)
		}
	}
	s.attest = map[string]bool{}
	for _, info := range s.blobs {
		if info.kind != kindIndex {
			continue
		}
		for _, child := range info.index.Manifests {
			if isAttestation(child) {
				s.attest[child.Digest.String()] = true
			}
		}
	}
	return nil
}

// isAttestation reports whether an index entry is a BuildKit attestation manifest: by its reference type
// annotation, or by its unknown/unknown platform. Such a manifest has an image config of its own, so its media
// types alone do not tell it from an image.
func isAttestation(d v1.Descriptor) bool {
	if d.Annotations[refTypeAnnotation] == refTypeAttestation {
		return true
	}
	return d.Platform != nil && d.Platform.OS == "unknown" && d.Platform.Architecture == "unknown"
}

// probe tells the blob kinds apart by which keys are present.
type probe struct {
	Manifests    json.RawMessage `json:"manifests"`
	Config       json.RawMessage `json:"config"`
	Layers       json.RawMessage `json:"layers"`
	Architecture *string         `json:"architecture"`
	OS           *string         `json:"os"`
	Variant      string          `json:"variant"`
}

// classify reads one blob: only a blob of at most MaxManifestBytes whose first byte is '{' is read in full.
func (s *Store) classify(digest string) (*blobInfo, error) {
	f, err := os.Open(s.blobPath(digest))
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	info := &blobInfo{kind: kindOther}
	if fi.Size() > MaxManifestBytes || fi.Size() == 0 {
		return info, nil
	}
	first := make([]byte, 1)
	if _, err := io.ReadFull(f, first); err != nil {
		return nil, err
	}
	if first[0] != '{' {
		return info, nil
	}
	rest, err := io.ReadAll(io.LimitReader(f, MaxManifestBytes))
	if err != nil {
		return nil, err
	}
	s.fullReads++
	b := append(first, rest...)
	var p probe
	if json.Unmarshal(b, &p) != nil {
		return info, nil
	}
	switch {
	case p.Manifests != nil:
		if idx, err := v1.ParseIndexManifest(bytes.NewReader(b)); err == nil {
			info.kind, info.index = kindIndex, idx
		}
	case p.Config != nil && p.Layers != nil:
		if m, err := v1.ParseManifest(bytes.NewReader(b)); err == nil {
			info.kind, info.manifest = kindManifest, m
		}
	case p.Architecture != nil && p.OS != nil:
		info.kind = kindConfig
		info.platform = platformString(*p.OS, *p.Architecture, p.Variant)
	}
	return info, nil
}

func platformString(os, arch, variant string) string {
	if os == "" || arch == "" {
		return ""
	}
	if variant != "" {
		return os + "/" + arch + "/" + variant
	}
	return os + "/" + arch
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// isImageManifest reports whether the blob d is a manifest of a runnable image: not an artifact (a config that is
// not an image config) and not an attestation (named as one by an index, or with an unknown/unknown config).
func (s *Store) isImageManifest(d string, info *blobInfo) bool {
	if info == nil || info.kind != kindManifest || !info.manifest.Config.MediaType.IsConfig() || s.attest[d] {
		return false
	}
	return s.configPlatform(info.manifest) != "unknown/unknown"
}

// manifestMediaType is the manifest's own media type, defaulting to OCI when it does not say.
func manifestMediaType(m *v1.Manifest) string {
	if m.MediaType != "" {
		return string(m.MediaType)
	}
	return string(types.OCIManifestSchema1)
}

func indexMediaType(idx *v1.IndexManifest) string {
	if idx.MediaType != "" {
		return string(idx.MediaType)
	}
	return string(types.OCIImageIndex)
}

// imageSize is the config size plus the layer sizes of a manifest.
func imageSize(m *v1.Manifest) int64 {
	n := m.Config.Size
	for _, l := range m.Layers {
		n += l.Size
	}
	return n
}

// complete reports whether the config and every layer of m are present.
func (s *Store) complete(m *v1.Manifest) bool {
	if _, ok := s.blobs[m.Config.Digest.String()]; !ok {
		return false
	}
	for _, l := range m.Layers {
		if _, ok := s.blobs[l.Digest.String()]; !ok {
			return false
		}
	}
	return true
}

// indexPlatforms maps each manifest digest an index entry names with a platform to that platform.
func (s *Store) indexPlatforms() map[string]string {
	out := map[string]string{}
	for _, info := range s.blobs {
		if info.kind != kindIndex {
			continue
		}
		for _, child := range info.index.Manifests {
			if p := descriptorPlatform(child); p != "" {
				out[child.Digest.String()] = p
			}
		}
	}
	return out
}

func descriptorPlatform(d v1.Descriptor) string {
	if d.Platform == nil {
		return ""
	}
	return platformString(d.Platform.OS, d.Platform.Architecture, d.Platform.Variant)
}

// configPlatform is the platform recorded in a manifest's config blob, "" when the blob is absent or says none.
func (s *Store) configPlatform(m *v1.Manifest) string {
	if c, ok := s.blobs[m.Config.Digest.String()]; ok && c.kind == kindConfig {
		return c.platform
	}
	return ""
}

// Scan lists the image manifests and indexes in the content store, sorted by digest. Blob classifications are
// cached per digest; completeness is checked on every Scan. A missing store gives an error wrapping
// fs.ErrNotExist and an unreadable one an error wrapping fs.ErrPermission.
func (s *Store) Scan(ctx context.Context) ([]wire.CachedImage, error) {
	if err := s.refresh(ctx); err != nil {
		return nil, err
	}
	images := map[string]wire.CachedImage{}
	var fromIndex map[string]string
	for d, info := range s.blobs {
		if !s.isImageManifest(d, info) {
			continue
		}
		platform := s.configPlatform(info.manifest)
		if platform == "" {
			if fromIndex == nil {
				fromIndex = s.indexPlatforms()
			}
			platform = fromIndex[d]
		}
		images[d] = wire.CachedImage{
			Digest:       d,
			MediaType:    manifestMediaType(info.manifest),
			ConfigDigest: info.manifest.Config.Digest.String(),
			Platform:     platform,
			Size:         imageSize(info.manifest),
			Complete:     s.complete(info.manifest),
		}
	}
	out := make([]wire.CachedImage, 0, len(images))
	for _, img := range images {
		out = append(out, img)
	}
	for d, info := range s.blobs {
		if info.kind != kindIndex {
			continue
		}
		ci := wire.CachedImage{Digest: d, MediaType: indexMediaType(info.index)}
		for _, child := range info.index.Manifests {
			ci.Manifests = append(ci.Manifests, child.Digest.String())
		}
		ci.Size, ci.Complete = s.indexTotals(info.index, images, 0)
		out = append(out, ci)
	}
	slices.SortFunc(out, func(a, b wire.CachedImage) int { return cmp.Compare(a.Digest, b.Digest) })
	return out, nil
}

// indexTotals sums the Size of the index's present image children and reports whether any is complete,
// following nested indexes up to maxIndexDepth.
func (s *Store) indexTotals(idx *v1.IndexManifest, images map[string]wire.CachedImage, depth int) (int64, bool) {
	var size int64
	complete := false
	for _, child := range idx.Manifests {
		d := child.Digest.String()
		if img, ok := images[d]; ok {
			size += img.Size
			complete = complete || img.Complete
			continue
		}
		if info, ok := s.blobs[d]; ok && info.kind == kindIndex && depth < maxIndexDepth {
			n, c := s.indexTotals(info.index, images, depth+1)
			size += n
			complete = complete || c
		}
	}
	return size, complete
}

// Target is one image manifest to stage: its media type, digest, config and layers, and Size = config + layers.
type Target struct {
	MediaType, Manifest, Config string
	Layers                      []string
	Size                        int64
}

func targetOf(digest string, m *v1.Manifest) Target {
	t := Target{MediaType: manifestMediaType(m), Manifest: digest, Config: m.Config.Digest.String(), Size: imageSize(m)}
	for _, l := range m.Layers {
		t.Layers = append(t.Layers, l.Digest.String())
	}
	return t
}

// Resolve finds the image manifest for digest: the manifest itself; for an index, the child matching platform
// ("os/arch" matches any variant, "os/arch/variant" only that one), through nested indexes; for a config digest
// (as kubelet reports side-loaded images), the manifest naming it, complete manifests first, then lowest digest.
// Anything else gives an error wrapping ErrNotFound. The store is re-listed once when the answer is not cached.
func (s *Store) Resolve(ctx context.Context, digest, platform string) (Target, error) {
	t, err := s.resolve(digest, platform)
	if !errors.Is(err, ErrNotFound) {
		return t, err
	}
	if err := s.refresh(ctx); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Target{}, fmt.Errorf("%w: %w", ErrNotFound, err)
		}
		return Target{}, err
	}
	return s.resolve(digest, platform)
}

func (s *Store) resolve(digest, platform string) (Target, error) {
	info, ok := s.blobs[digest]
	if !ok {
		return Target{}, fmt.Errorf("%w: %s", ErrNotFound, digest)
	}
	switch info.kind {
	case kindManifest:
		if !s.isImageManifest(digest, info) {
			return Target{}, fmt.Errorf("%w: %s is not an image manifest", ErrNotFound, digest)
		}
		return targetOf(digest, info.manifest), nil
	case kindIndex:
		if platform == "" {
			return Target{}, fmt.Errorf("%w: %s is an index and no platform was given", ErrNotFound, digest)
		}
		if t, ok := s.resolveIndex(info.index, platform, 0); ok {
			return t, nil
		}
		return Target{}, fmt.Errorf("%w: index %s holds no %s image", ErrNotFound, digest, platform)
	case kindConfig:
		var best string
		bestComplete := false
		for d, m := range s.blobs {
			if !s.isImageManifest(d, m) || m.manifest.Config.Digest.String() != digest {
				continue
			}
			c := s.complete(m.manifest)
			if best == "" || (c && !bestComplete) || (c == bestComplete && d < best) {
				best, bestComplete = d, c
			}
		}
		if best == "" {
			return Target{}, fmt.Errorf("%w: no manifest names config %s", ErrNotFound, digest)
		}
		return targetOf(best, s.blobs[best].manifest), nil
	}
	return Target{}, fmt.Errorf("%w: %s is not an image, index or image config", ErrNotFound, digest)
}

func (s *Store) resolveIndex(idx *v1.IndexManifest, platform string, depth int) (Target, bool) {
	for _, child := range idx.Manifests {
		d := child.Digest.String()
		info, ok := s.blobs[d]
		if !ok {
			continue
		}
		switch {
		case isAttestation(child):
			continue
		case s.isImageManifest(d, info):
			p := descriptorPlatform(child)
			if p == "" {
				p = s.configPlatform(info.manifest)
			}
			if platformMatches(p, platform) {
				return targetOf(d, info.manifest), true
			}
		case info.kind == kindIndex && depth < maxIndexDepth:
			if t, ok := s.resolveIndex(info.index, platform, depth+1); ok {
				return t, true
			}
		}
	}
	return Target{}, false
}

// platformMatches reports whether have ("os/arch[/variant]") satisfies want: "os/arch" matches any variant,
// "os/arch/variant" only that variant.
func platformMatches(have, want string) bool {
	if have == "" {
		return false
	}
	if have == want {
		return true
	}
	return strings.Count(want, "/") == 1 && strings.HasPrefix(have, want+"/")
}
