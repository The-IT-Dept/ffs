package inventory

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/registry"
	"github.com/the-it-dept/ffs/internal/sbom"
)

// ReasonBadReference is the unresolvable reason for a template image reference that cannot be
// parsed; %q is the reference and %v the parse error.
const ReasonBadReference = "image reference %q cannot be parsed: %v"

// use is one container's image use, with the normalised image row and the pull credentials behind it.
type use struct {
	model.ContainerUse
	Image model.Image
	Creds registry.CredSet
}

func newUse(name string, kind model.ContainerKind, ref string, img model.Image, cs registry.CredSet, root bool) use {
	return use{ContainerUse: model.ContainerUse{Name: name, Kind: kind, ImageRef: ref, Repo: img.Repo, Digest: img.Digest,
		Platform: img.Platform, RootUnlessImageUser: root}, Image: img, Creds: cs}
}

// credsFor returns the pull credentials a pod spec runs with.
func credsFor(namespace string, spec *corev1.PodSpec) registry.CredSet {
	return registry.CredSet{Namespace: namespace, ServiceAccount: serviceAccount(spec), PullSecrets: pullSecretNames(spec)}
}

func serviceAccount(spec *corev1.PodSpec) string {
	if spec.ServiceAccountName != "" {
		return spec.ServiceAccountName
	}
	return "default"
}

func pullSecretNames(spec *corev1.PodSpec) []string {
	var out []string
	for _, s := range spec.ImagePullSecrets {
		out = append(out, s.Name)
	}
	return out
}

// rootUnlessImageUser reports whether the effective runAsUser (container, falling back to pod) is
// unset and the effective runAsNonRoot is not true, so the image's own user decides.
func rootUnlessImageUser(pod *corev1.PodSecurityContext, c *corev1.SecurityContext) bool {
	var (
		uid     *int64
		nonRoot *bool
	)
	if c != nil {
		uid, nonRoot = c.RunAsUser, c.RunAsNonRoot
	}
	if pod != nil {
		if uid == nil {
			uid = pod.RunAsUser
		}
		if nonRoot == nil {
			nonRoot = pod.RunAsNonRoot
		}
	}
	return uid == nil && (nonRoot == nil || !*nonRoot)
}

func initKind(c *corev1.Container) model.ContainerKind {
	if c != nil && c.RestartPolicy != nil && *c.RestartPolicy == corev1.ContainerRestartPolicyAlways {
		return model.ContainerSidecar
	}
	return model.ContainerInit
}

// placeholder is the use of a container whose image could not be resolved yet: it keeps the
// container in the owner, with no digest, until a retry resolves it.
func placeholder(name string, kind model.ContainerKind, ref string, platform NodePlatform, cs registry.CredSet, root bool) use {
	repo, _, _, _ := SplitRef(ref)
	return newUse(name, kind, ref, model.Image{Repo: repo, Platform: platform.Key()}, cs, root)
}

// partial collects the containers whose image failed to resolve, so the owner is still stored
// with every other container and retried for these.
type partial struct{ errs []error }

// add records err for one container; it reports false when err must abort the whole owner
// (shutdown).
func (p *partial) add(ctx context.Context, what string, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	p.errs = append(p.errs, fmt.Errorf("%s: %w", what, err))
	return true
}

func (p *partial) err() error { return errors.Join(p.errs...) }

// containerUses reads a running pod's container statuses (regular, init and native sidecars,
// ephemeral) and its image volumes. Containers that have not reported an image ID are omitted. A
// container whose image fails to resolve becomes a placeholder use, and the returned error lists
// those failures; the other uses are still returned.
func (inv *Inventory) containerUses(ctx context.Context, pod *corev1.Pod, node NodePlatform, prev prevUses) ([]use, error) {
	cs := credsFor(pod.Namespace, &pod.Spec)
	// Container names are unique across regular, init and ephemeral containers.
	type spec struct {
		image string
		sc    *corev1.SecurityContext
		kind  model.ContainerKind
	}
	specs := map[string]spec{}
	for _, c := range pod.Spec.Containers {
		specs[c.Name] = spec{c.Image, c.SecurityContext, model.ContainerRegular}
	}
	for i := range pod.Spec.InitContainers {
		c := &pod.Spec.InitContainers[i]
		specs[c.Name] = spec{c.Image, c.SecurityContext, initKind(c)}
	}
	for _, c := range pod.Spec.EphemeralContainers {
		specs[c.Name] = spec{c.Image, c.SecurityContext, model.ContainerEphemeral}
	}

	var (
		out   []use
		fails partial
	)
	for _, group := range []struct {
		statuses []corev1.ContainerStatus
		kind     model.ContainerKind
	}{
		{pod.Status.ContainerStatuses, model.ContainerRegular},
		{pod.Status.InitContainerStatuses, model.ContainerInit},
		{pod.Status.EphemeralContainerStatuses, model.ContainerEphemeral},
	} {
		for _, st := range group.statuses {
			if st.ImageID == "" {
				continue
			}
			s, ok := specs[st.Name]
			if !ok {
				s.kind = group.kind
			}
			ref := st.Image
			if ref == "" {
				ref = s.image
			}
			root := rootUnlessImageUser(pod.Spec.SecurityContext, s.sc)
			img, err := inv.o.Normalizer.Normalize(ctx, ContainerImage{Image: ref, ImageID: st.ImageID, Node: node, Creds: cs})
			if err != nil {
				if !fails.add(ctx, "container "+st.Name, err) {
					return nil, err
				}
				out = append(out, placeholder(st.Name, s.kind, ref, node, cs, root))
				continue
			}
			out = append(out, newUse(st.Name, s.kind, ref, img, cs, root))
		}
	}

	for _, v := range pod.Spec.Volumes {
		if v.Image == nil {
			continue
		}
		var (
			img model.Image
			err error
		)
		if id := volumeImageRef(pod, v.Name); id != "" {
			img, err = inv.o.Normalizer.Normalize(ctx, ContainerImage{Image: v.Image.Reference, ImageID: id, Node: node, Creds: cs})
		} else {
			img, err = inv.resolveRef(ctx, v.Image.Reference, node, cs, prev.of(v.Name, model.ContainerImageVolume, v.Image.Reference))
		}
		if err != nil {
			if !fails.add(ctx, "image volume "+v.Name, err) {
				return nil, err
			}
			out = append(out, placeholder(v.Name, model.ContainerImageVolume, v.Image.Reference, node, cs, false))
			continue
		}
		out = append(out, newUse(v.Name, model.ContainerImageVolume, v.Image.Reference, img, cs, false))
	}
	return out, fails.err()
}

// volumeImageRef returns the kubelet-reported image ref of an image volume, or "".
func volumeImageRef(pod *corev1.Pod, volume string) string {
	for _, sts := range [][]corev1.ContainerStatus{pod.Status.ContainerStatuses, pod.Status.InitContainerStatuses,
		pod.Status.EphemeralContainerStatuses} {
		for _, st := range sts {
			for _, m := range st.VolumeMounts {
				if m.Name == volume && m.VolumeStatus != nil && m.VolumeStatus.Image != nil && m.VolumeStatus.Image.ImageRef != "" {
					return m.VolumeStatus.Image.ImageRef
				}
			}
		}
	}
	return ""
}

// templateUses resolves a workload template's images (init containers, native sidecars,
// containers and image volumes) at the given platform. Like containerUses, an image that fails to
// resolve becomes a placeholder use and its failure is returned with the other uses.
func (inv *Inventory) templateUses(ctx context.Context, tmpl *corev1.PodTemplateSpec, namespace string, platform NodePlatform,
	prev prevUses) ([]use, error) {
	cs := credsFor(namespace, &tmpl.Spec)
	psc := tmpl.Spec.SecurityContext
	var (
		out   []use
		fails partial
	)
	add := func(name string, kind model.ContainerKind, ref string, root bool) error {
		img, err := inv.resolveRef(ctx, ref, platform, cs, prev.of(name, kind, ref))
		if err != nil {
			if !fails.add(ctx, fmt.Sprintf("%s %s", kind, name), err) {
				return err
			}
			out = append(out, placeholder(name, kind, ref, platform, cs, root))
			return nil
		}
		out = append(out, newUse(name, kind, ref, img, cs, root))
		return nil
	}
	for i := range tmpl.Spec.InitContainers {
		c := &tmpl.Spec.InitContainers[i]
		if err := add(c.Name, initKind(c), c.Image, rootUnlessImageUser(psc, c.SecurityContext)); err != nil {
			return nil, err
		}
	}
	for _, c := range tmpl.Spec.Containers {
		if err := add(c.Name, model.ContainerRegular, c.Image, rootUnlessImageUser(psc, c.SecurityContext)); err != nil {
			return nil, err
		}
	}
	for _, v := range tmpl.Spec.Volumes {
		if v.Image != nil {
			if err := add(v.Name, model.ContainerImageVolume, v.Image.Reference, false); err != nil {
				return nil, err
			}
		}
	}
	return out, fails.err()
}

// prevUses are the container uses an owner was stored with, by container name, kind and image
// reference.
type prevUses map[prevKey]model.ContainerUse

type prevKey struct {
	name string
	kind model.ContainerKind
	ref  string
}

func prevUsesOf(o model.Owner) prevUses {
	out := prevUses{}
	for _, c := range o.Containers {
		if c.Digest != "" {
			out[prevKey{c.Name, c.Kind, c.ImageRef}] = c
		}
	}
	return out
}

// of returns the stored use of the container, or nil.
func (p prevUses) of(name string, kind model.ContainerKind, ref string) *model.ContainerUse {
	if c, ok := p[prevKey{name, kind, ref}]; ok {
		return &c
	}
	return nil
}

// resolveRef resolves an image reference that has no kubelet-reported image ID: a workload
// template, or an image volume the kubelet has not reported. Nothing has pulled it for this
// workload, so a digest is used only once the registry has confirmed that cs may pull it (a HEAD,
// which costs no manifest budget). Otherwise a reference to another namespace's private image would
// attach that image's packages and CVEs to this workload. A confirmation holds for TagTTL per
// credentials, repository and digest.
//
// A tag goes through the recorded tag digest while the record is younger than TagTTL, confirmed for
// cs and, during a TagTTL refresh, written since the refresh started (see refreshTemplates), else a
// registry HEAD under cs; a reference pinned by digest is confirmed with a HEAD. A refusal yields an
// unresolvable placeholder, never a digest recorded for someone else. When a lookup fails for any
// other reason, the image prev (this container's stored use) had is kept.
//
// A lookup that ended in an unresolvable placeholder is not repeated for the same credentials and
// platform while its miss holds (missTTL, doubling up to maxMissTTL), so a tag that never resolves
// does not cost a registry call on every flush of its owners. A refusal's placeholder is used by
// every owner; after a registry that was not reachable, an owner keeps the image prev had, as after a
// failed lookup of its own, and only an owner with none takes the placeholder.
func (inv *Inventory) resolveRef(ctx context.Context, ref string, platform NodePlatform, cs registry.CredSet,
	prev *model.ContainerUse) (model.Image, error) {
	repo, tag, digest, err := SplitRef(ref)
	if err != nil {
		return inv.o.Normalizer.unresolvable("unknown:"+ref, "", platform.Key(), fmt.Sprintf(ReasonBadReference, ref, err)), nil
	}
	now := inv.now()
	lookup := ref // what a registry error is reported against
	if digest == "" {
		lookup = repo + ":" + tag
		recorded, at, ok, err := inv.o.Store.TagDigest(ctx, repo, tag)
		if err != nil {
			return model.Image{}, err
		}
		if ok && !at.Before(inv.tagsSince) && now.Sub(at) < inv.o.TagTTL && inv.access.confirmed(cs, repo, recorded, now) {
			digest = recorded
		} else {
			mk := missKeyOf(cs, lookup, platform)
			if m, ok := inv.misses.get(mk, now); ok {
				return inv.missed(ctx, m, repo, prev)
			}
			d, err := inv.o.Resolver.ResolveTag(ctx, repo, tag, cs)
			if err != nil {
				return inv.unconfirmed(ctx, err, mk, lookup, repo, platform, prev)
			}
			inv.misses.clear(mk)
			if err := inv.o.Store.PutTagDigest(ctx, repo, tag, d, now); err != nil {
				return model.Image{}, err
			}
			inv.access.confirm(cs, repo, d, now)
			digest = d
		}
	} else if !inv.access.confirmed(cs, repo, digest, now) {
		mk := missKeyOf(cs, lookup, platform)
		if m, ok := inv.misses.get(mk, now); ok {
			return inv.missed(ctx, m, repo, prev)
		}
		if _, err := inv.o.Resolver.Head(ctx, repo+"@"+digest, cs); err != nil {
			return inv.unconfirmed(ctx, err, mk, lookup, repo, platform, prev)
		}
		inv.misses.clear(mk)
		inv.access.confirm(cs, repo, digest, now)
	}
	return inv.o.Normalizer.Normalize(ctx, ContainerImage{Image: ref, ImageID: repo + "@" + digest, Node: platform, Creds: cs})
}

// unconfirmed handles a registry lookup that did not confirm access: a refusal is an unresolvable
// placeholder for the reference; another failure keeps prev's image when there is one, and is
// otherwise returned (or, after repeated failures, unresolvable as not reachable). A placeholder is
// recorded as a miss under mk, with whether the registry refused.
func (inv *Inventory) unconfirmed(ctx context.Context, err error, mk missKey, lookup, repo string, platform NodePlatform,
	prev *model.ContainerUse) (model.Image, error) {
	refused := errors.Is(err, registry.ErrUnauthorized) || errors.Is(err, registry.ErrNotFound)
	if !refused && ctx.Err() == nil {
		if img, ok, serr := inv.kept(ctx, repo, prev); serr != nil || ok {
			return img, serr
		}
	}
	placeholder := "unknown:" + lookup
	img, ferr := inv.o.Normalizer.fail(ctx, err, placeholder, repo, lookup, "", platform.Key())
	if ferr == nil && img.Digest == placeholder {
		img = inv.misses.add(mk, img, refused, inv.now())
	}
	return img, ferr
}

// missed answers a lookup that the miss m still covers, with no registry call: the placeholder it
// recorded, unless the registry was not reachable and prev had an image, which is kept.
func (inv *Inventory) missed(ctx context.Context, m miss, repo string, prev *model.ContainerUse) (model.Image, error) {
	if !m.refused {
		if img, ok, err := inv.kept(ctx, repo, prev); err != nil || ok {
			return img, err
		}
	}
	return m.img, nil
}

// kept returns the stored image of prev, this container's stored use, under repo; false when there is
// none.
func (inv *Inventory) kept(ctx context.Context, repo string, prev *model.ContainerUse) (model.Image, bool, error) {
	if prev == nil {
		return model.Image{}, false, nil
	}
	img, ok, err := inv.o.Store.GetImage(ctx, prev.Digest)
	if err != nil || !ok {
		return model.Image{}, false, err
	}
	img.Repo = repo
	return img, true, nil
}

// recordImage stores a new image row (or a refreshed unresolvable one) and collects an SBOM request
// for an image that is not handed to the acquirer already: a pending one, or one whose catalogFailed
// quarantine has ended (the retry spec §6.3 promises, which must survive a restart).
//
// What is outstanding is read from the store. A hand-off is outstanding until the stored row shows
// a quarantine written after it (the acquirer's attempt failed: catalogFailed or unresolvable with
// a later end), so an image the acquirer quarantined is handed back once that quarantine ends, by
// this process and without its owner changing (the RetryPoll flushes the owners the store lists).
func (inv *Inventory) recordImage(ctx context.Context, f *flushState, u use) error {
	img := u.Image
	if img.Digest == "" {
		return nil // a placeholder: nothing resolved yet
	}
	stored, ok, err := inv.o.Store.GetImage(ctx, img.Digest)
	if err != nil {
		return err
	}
	refreshed := ok && stored.Status == model.ImageUnresolvable && img.Status == model.ImageUnresolvable &&
		img.QuarantinedUntil.After(stored.QuarantinedUntil)
	if !ok || refreshed {
		if err := inv.o.Store.UpsertImage(ctx, img); err != nil {
			return err
		}
	}
	if ok && !refreshed && quarantined(stored) && f.now.Before(stored.QuarantinedUntil) {
		// Still quarantined, whatever the normaliser resolved (a side-loaded image resolves through
		// the registry to a platform manifest the acquirer quarantined, say): nothing to hand off.
		delete(inv.enqueued, img.Digest)
		return nil
	}
	if at, handed := inv.enqueued[img.Digest]; handed && ok && quarantined(stored) && stored.QuarantinedUntil.After(at) {
		delete(inv.enqueued, img.Digest) // the hand-off ended in a quarantine, which has ended too
	}
	if ok && stored.Status == model.ImageCatalogued && stored.Source == sbom.SourceAgent {
		// Catalogued from a node agent's SBOM: ask the registry for its own, at most once per
		// UnresolvableRetry. The acquirer replaces the agent SBOM only when that succeeds.
		if at, asked := inv.superseded[img.Digest]; !asked || f.now.Sub(at) >= UnresolvableRetry {
			inv.superseded[img.Digest] = f.now
			f.reqs = append(f.reqs, sbom.Request{Repo: img.Repo, Digest: img.Digest, IndexDigest: img.IndexDigest,
				Platform: img.Platform, Creds: u.Creds, Supersede: true})
		}
		delete(inv.enqueued, img.Digest)
		return nil
	}
	delete(inv.superseded, img.Digest)
	due := img.Status == model.ImageCatalogFailed && !f.now.Before(img.QuarantinedUntil)
	if img.Status != model.ImagePending && !due {
		delete(inv.enqueued, img.Digest)
		return nil
	}
	if _, handed := inv.enqueued[img.Digest]; !handed {
		inv.enqueued[img.Digest] = f.now
		f.reqs = append(f.reqs, sbom.Request{Repo: img.Repo, Digest: img.Digest, IndexDigest: img.IndexDigest,
			Platform: img.Platform, Creds: u.Creds})
	}
	return nil
}

// quarantined reports whether img holds a catalogFailed or unresolvable quarantine, ended or not.
// An image is handed off only while it holds none in force, so a quarantine that ends after a
// hand-off was written by an attempt that followed it.
func quarantined(img model.Image) bool {
	return img.Status == model.ImageCatalogFailed || img.Status == model.ImageUnresolvable
}

func hasImageID(p *corev1.Pod) bool {
	for _, sts := range [][]corev1.ContainerStatus{p.Status.ContainerStatuses, p.Status.InitContainerStatuses,
		p.Status.EphemeralContainerStatuses} {
		for _, st := range sts {
			if st.ImageID != "" {
				return true
			}
		}
	}
	return false
}

// containerList de-duplicates the uses and sorts them by name, then digest.
func containerList(uses []use) []model.ContainerUse {
	// ExposurePaths is a slice, so it cannot be part of a map key; workload uses never set it.
	type key struct {
		Name, ImageRef, Repo, Digest, Platform string
		Kind                                   model.ContainerKind
		Root                                   bool
	}
	seen := map[key]bool{}
	var out []model.ContainerUse
	for _, u := range uses {
		k := key{u.Name, u.ImageRef, u.Repo, u.Digest, u.Platform, u.Kind, u.RootUnlessImageUser}
		if !seen[k] {
			seen[k] = true
			out = append(out, u.ContainerUse)
		}
	}
	slices.SortFunc(out, func(a, b model.ContainerUse) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Digest, b.Digest),
			strings.Compare(fmt.Sprint(a), fmt.Sprint(b)))
	})
	return out
}
