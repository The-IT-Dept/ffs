package inventory

import (
	"cmp"
	"context"
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

// containerUses reads a running pod's container statuses (regular, init and native sidecars,
// ephemeral) and its image volumes. Containers that have not reported an image ID are omitted.
func (inv *Inventory) containerUses(ctx context.Context, pod *corev1.Pod, node NodePlatform) ([]use, error) {
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

	var out []use
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
			img, err := inv.o.Normalizer.Normalize(ctx, ContainerImage{Image: ref, ImageID: st.ImageID, Node: node, Creds: cs})
			if err != nil {
				return nil, fmt.Errorf("container %s: %w", st.Name, err)
			}
			out = append(out, newUse(st.Name, s.kind, ref, img, cs, rootUnlessImageUser(pod.Spec.SecurityContext, s.sc)))
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
			img, err = inv.resolveRef(ctx, v.Image.Reference, node, cs)
		}
		if err != nil {
			return nil, fmt.Errorf("image volume %s: %w", v.Name, err)
		}
		out = append(out, newUse(v.Name, model.ContainerImageVolume, v.Image.Reference, img, cs, false))
	}
	return out, nil
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
// containers and image volumes) at the given platform.
func (inv *Inventory) templateUses(ctx context.Context, tmpl *corev1.PodTemplateSpec, namespace string, platform NodePlatform) ([]use, error) {
	cs := credsFor(namespace, &tmpl.Spec)
	psc := tmpl.Spec.SecurityContext
	var out []use
	add := func(name string, kind model.ContainerKind, ref string, root bool) error {
		img, err := inv.resolveRef(ctx, ref, platform, cs)
		if err != nil {
			return fmt.Errorf("%s %s: %w", kind, name, err)
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
	return out, nil
}

// resolveRef resolves an image reference that has no kubelet-reported image ID. A tag goes
// through the recorded tag digest while it is younger than TagTTL, else a registry HEAD; a
// reference pinned by digest skips tag resolution. When a fresh lookup fails, the last recorded
// digest is used; with none, a permanent failure yields an unresolvable placeholder image.
func (inv *Inventory) resolveRef(ctx context.Context, ref string, platform NodePlatform, cs registry.CredSet) (model.Image, error) {
	repo, tag, digest, err := SplitRef(ref)
	if err != nil {
		return inv.o.Normalizer.unresolvable("unknown:"+ref, "", platform.Key(), fmt.Sprintf(ReasonBadReference, ref, err)), nil
	}
	if digest == "" {
		now := inv.now()
		recorded, at, ok, err := inv.o.Store.TagDigest(ctx, repo, tag)
		if err != nil {
			return model.Image{}, err
		}
		digest = recorded
		if !ok || now.Sub(at) >= inv.o.TagTTL {
			d, err := inv.o.Resolver.ResolveTag(ctx, repo, tag, cs)
			switch {
			case err == nil:
				if err := inv.o.Store.PutTagDigest(ctx, repo, tag, d, now); err != nil {
					return model.Image{}, err
				}
				digest = d
			case !ok:
				tagRef := repo + ":" + tag
				return inv.o.Normalizer.fail(err, "unknown:"+tagRef, repo, tagRef, "", platform.Key())
			}
		}
	}
	return inv.o.Normalizer.Normalize(ctx, ContainerImage{Image: ref, ImageID: repo + "@" + digest, Node: platform, Creds: cs})
}

// recordImage stores a new image row (or a refreshed unresolvable one) and collects an SBOM request
// for a pending image this process has not yet handed to the acquirer.
func (inv *Inventory) recordImage(ctx context.Context, f *flushState, u use) error {
	img := u.Image
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
	if img.Status != model.ImagePending {
		delete(inv.enqueued, img.Digest)
		return nil
	}
	if !inv.enqueued[img.Digest] {
		inv.enqueued[img.Digest] = true
		f.reqs = append(f.reqs, sbom.Request{Repo: img.Repo, Digest: img.Digest, IndexDigest: img.IndexDigest,
			Platform: img.Platform, Creds: u.Creds})
	}
	return nil
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
	seen := map[model.ContainerUse]bool{}
	var out []model.ContainerUse
	for _, u := range uses {
		if !seen[u.ContainerUse] {
			seen[u.ContainerUse] = true
			out = append(out, u.ContainerUse)
		}
	}
	slices.SortFunc(out, func(a, b model.ContainerUse) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Digest, b.Digest),
			strings.Compare(fmt.Sprint(a), fmt.Sprint(b)))
	})
	return out
}
