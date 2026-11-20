package inventory

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/the-it-dept/ffs/internal/model"
)

const (
	// NoteBundled is the coverage note on every Kubernetes synthetic image.
	NoteBundled = "kernel, runc and other bundled components (flannel) are not inventoried"
	// NoteVendorVersion is added for managed-distribution versions; %s is the raw version.
	NoteVendorVersion = "version normalised from %s; vendor builds may include backported fixes"

	kindCluster     = model.OwnerKindCluster
	kindRuntime     = model.OwnerKindContainerRuntime
	sourceInventory = "inventory"
)

var k8sVersion = regexp.MustCompile(`^v?(\d+\.\d+\.\d+)`)

// NormalizeK8sVersion reduces a gitVersion such as "v1.35.2+k3s1" or "v1.30.4-eks-a737599" to the
// upstream version, and names the distribution from the suffix. Managed distributions (eks, gke)
// are low confidence, because vendor builds may carry backported fixes.
func NormalizeK8sVersion(gitVersion string) (version, distribution string, lowConfidence bool, err error) {
	m := k8sVersion.FindStringSubmatch(gitVersion)
	if m == nil {
		return "", "", false, fmt.Errorf("inventory: %q is not a Kubernetes version", gitVersion)
	}
	suffix := gitVersion[len(m[0]):]
	switch {
	case strings.Contains(suffix, "+k3s"):
		distribution = "k3s"
	case strings.Contains(suffix, "+rke2"):
		distribution = "rke2"
	case strings.Contains(suffix, "-eks-"):
		distribution, lowConfidence = "eks", true
	case strings.Contains(suffix, "-gke."):
		distribution, lowConfidence = "gke", true
	}
	return m[1], distribution, lowConfidence, nil
}

// ParseRuntimeVersion splits a node containerRuntimeVersion such as "containerd://1.7.23-k3s2"
// into the runtime name and its upstream version ("containerd", "1.7.23").
func ParseRuntimeVersion(v string) (name, version string, ok bool) {
	name, version, found := strings.Cut(v, "://")
	if !found {
		return "", "", false
	}
	if i := strings.IndexAny(version, "-+"); i >= 0 {
		version = version[:i]
	}
	version = strings.TrimPrefix(version, "v")
	if name == "" || version == "" {
		return "", "", false
	}
	return name, version, true
}

// Synthetic is a cluster-level owner with its synthetic images and their packages, keyed by digest.
type Synthetic struct {
	Owner    model.Owner
	Images   []model.Image
	Packages map[string][]model.Package
}

// ClusterOptions adjusts BuildClusterInventory.
type ClusterOptions struct {
	// RuntimeRetired: the node agent reports the container runtime (the Nodes owner), so no
	// ContainerRuntime owners are built and the Kubernetes images drop NoteBundled.
	RuntimeRetired bool
	// KubeProxyTag is the kube-proxy image tag ci.KubeProxyVersion was normalised from, such as
	// "v1.30.4-eksbuild.3"; "" when unknown.
	KubeProxyTag string
}

// BuildClusterInventory builds the synthetic Cluster owner (control plane, kubelet and kube-proxy
// versions as "k8s:<v>" digests) and, unless o.RuntimeRetired, one ContainerRuntime owner per
// containerd or CRI-O runtime ("runtime:<name>@<v>" digests). An owner with no versions is not
// emitted.
func BuildClusterInventory(clusterName string, ci model.ClusterInfo, nodes []model.Node, now time.Time, o ClusterOptions) []Synthetic {
	var out []Synthetic
	if s, ok := clusterSynthetic(clusterName, ci, nodes, now, o); ok {
		out = append(out, s)
	}
	if o.RuntimeRetired {
		return out
	}
	return append(out, runtimeSynthetics(nodes, now)...)
}

type k8sRoles struct {
	controlPlane              bool
	kubelets                  int
	kubeProxy                 bool
	kubeletRaw, kubeletLowRaw string // smallest raw kubelet version, and smallest low-confidence one
}

// smallest keeps the smallest non-empty raw version, so the result does not depend on node order.
func smallest(cur, v string) string {
	if cur == "" || v < cur {
		return v
	}
	return cur
}

func clusterSynthetic(clusterName string, ci model.ClusterInfo, nodes []model.Node, now time.Time, o ClusterOptions) (Synthetic, bool) {
	versions := map[string]*k8sRoles{}
	get := func(v string) *k8sRoles {
		if versions[v] == nil {
			versions[v] = &k8sRoles{}
		}
		return versions[v]
	}
	if ci.Version != "" {
		get(ci.Version).controlPlane = true
	}
	for _, n := range nodes {
		v, _, low, err := NormalizeK8sVersion(n.KubeletVersion)
		if err != nil {
			continue
		}
		r := get(v)
		r.kubelets++
		r.kubeletRaw = smallest(r.kubeletRaw, n.KubeletVersion)
		if low {
			r.kubeletLowRaw = smallest(r.kubeletLowRaw, n.KubeletVersion)
		}
	}
	if len(versions) == 0 { // kube-proxy alone does not make a Cluster owner
		return Synthetic{}, false
	}
	if ci.KubeProxyVersion != "" {
		get(ci.KubeProxyVersion).kubeProxy = true
	}

	s := Synthetic{
		Owner:    model.Owner{Ref: model.OwnerRef{Kind: kindCluster, Name: clusterName}, UpdatedAt: now},
		Packages: map[string][]model.Package{},
	}
	for _, v := range sortedKeys(versions) {
		r := versions[v]
		d := "k8s:" + v
		var roles []string
		if r.controlPlane {
			roles = append(roles, "control plane")
		}
		if r.kubelets > 0 {
			roles = append(roles, "kubelet on "+nodeCount(r.kubelets))
		}
		if r.kubeProxy {
			roles = append(roles, "kube-proxy")
		}
		raw, lowRaw := r.kubeletRaw, r.kubeletLowRaw
		switch {
		case r.controlPlane:
			raw = ci.GitVersion
			if ci.LowConfidence {
				lowRaw = ci.GitVersion
			}
		case raw == "" && r.kubeProxy:
			// Only kube-proxy runs this version. On a managed distribution it is a vendor build too,
			// whose tag rarely names the vendor (EKS's "-eksbuild.<n>").
			raw = "v" + v
			if o.KubeProxyTag != "" {
				raw = o.KubeProxyTag
			}
			if _, _, low, err := NormalizeK8sVersion(raw); ci.LowConfidence || (err == nil && low) {
				lowRaw = raw
			}
		case raw == "":
			raw = "v" + v
		}
		var notes []string
		if !o.RuntimeRetired {
			notes = append(notes, NoteBundled)
		}
		if lowRaw != "" {
			notes = append(notes, fmt.Sprintf(NoteVendorVersion, lowRaw))
		}
		s.Owner.Containers = append(s.Owner.Containers, model.ContainerUse{Name: "kubernetes", Kind: model.ContainerRegular,
			ImageRef: raw, Repo: "kubernetes", Digest: d})
		s.Images = append(s.Images, syntheticImage(d, "kubernetes", notes, now))
		s.Packages[d] = []model.Package{syntheticPackage(d, "kubernetes", "kubernetes", v, strings.Join(roles, "; "))}
	}
	return s, true
}

func runtimeSynthetics(nodes []model.Node, now time.Time) []Synthetic {
	type runtimeVersion struct {
		raw   string
		nodes int
	}
	byName := map[string]map[string]*runtimeVersion{}
	for _, n := range nodes {
		name, v, ok := ParseRuntimeVersion(n.ContainerRuntimeVersion)
		if !ok || (name != "containerd" && name != "cri-o") {
			continue
		}
		if byName[name] == nil {
			byName[name] = map[string]*runtimeVersion{}
		}
		rv := byName[name][v]
		if rv == nil {
			rv = &runtimeVersion{raw: n.ContainerRuntimeVersion}
			byName[name][v] = rv
		}
		rv.nodes++
		if n.ContainerRuntimeVersion < rv.raw {
			rv.raw = n.ContainerRuntimeVersion
		}
	}
	var out []Synthetic
	for _, name := range sortedKeys(byName) {
		s := Synthetic{
			Owner:    model.Owner{Ref: model.OwnerRef{Kind: kindRuntime, Name: name}, UpdatedAt: now},
			Packages: map[string][]model.Package{},
		}
		for _, v := range sortedKeys(byName[name]) {
			rv := byName[name][v]
			d := "runtime:" + name + "@" + v
			s.Owner.Containers = append(s.Owner.Containers, model.ContainerUse{Name: name, Kind: model.ContainerRegular,
				ImageRef: rv.raw, Repo: name, Digest: d})
			s.Images = append(s.Images, syntheticImage(d, name, nil, now))
			s.Packages[d] = []model.Package{syntheticPackage(d, "go-module", runtimeModule(name, v), "v"+v, nodeCount(rv.nodes))}
		}
		out = append(out, s)
	}
	return out
}

// runtimeModule returns the Go module whose advisories cover the runtime version.
func runtimeModule(name, version string) string {
	if name == "cri-o" {
		return "github.com/cri-o/cri-o"
	}
	major, _, _ := strings.Cut(version, ".")
	if n, err := strconv.Atoi(major); err == nil && n >= 2 {
		return "github.com/containerd/containerd/v2"
	}
	return "github.com/containerd/containerd"
}

func syntheticImage(digest, repo string, notes []string, now time.Time) model.Image {
	return model.Image{Digest: digest, Repo: repo, Status: model.ImageCatalogued, Source: sourceInventory,
		Coverage: model.Coverage{Notes: notes}, CataloguedAt: now}
}

func syntheticPackage(digest, ecosystem, name, version, path string) model.Package {
	p := model.Package{ImageDigest: digest, Ecosystem: ecosystem, Name: name, Version: version, Path: path}
	p.ID = model.PackageID(digest, p)
	return p
}

func nodeCount(n int) string {
	if n == 1 {
		return "1 node"
	}
	return strconv.Itoa(n) + " nodes"
}

// sortedKeys returns the map's keys in order, nil for an empty map.
func sortedKeys[V any](m map[string]V) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// flushCluster stores the nodes and control-plane version and brings the synthetic Cluster and
// ContainerRuntime owners up to date. While the node agent has retired the runtime owner
// (store.NodesState.RuntimeRetired), no ContainerRuntime owner is built. Synthetic owners are never
// deleted here: a ContainerRuntime owner is dropped only by engine.Rehome, which moves its findings
// onto the Nodes owner in the same write.
func (inv *Inventory) flushCluster(ctx context.Context, f *flushState) error {
	state, err := inv.o.Store.NodesState(ctx)
	if err != nil {
		return err
	}
	if err := inv.o.Store.ReplaceNodes(ctx, f.nodeList); err != nil {
		return err
	}
	ci, proxyTag, err := inv.clusterInfo(ctx, f.now)
	if err != nil {
		return err
	}
	if err := inv.o.Store.PutClusterInfo(ctx, ci); err != nil {
		return err
	}
	var errs []error
	opts := ClusterOptions{RuntimeRetired: state.RuntimeRetired, KubeProxyTag: proxyTag}
	for _, s := range BuildClusterInventory(inv.o.ClusterName, ci, f.nodeList, f.now, opts) {
		for _, img := range s.Images {
			if err := inv.recordSynthetic(ctx, img, s.Packages[img.Digest]); err != nil {
				errs = append(errs, err)
			}
		}
		if err := inv.storeOwner(ctx, f, s.Owner); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// recordSynthetic writes a new synthetic image with its packages, or re-puts the packages of a
// stored one whose package IDs changed (a Path change: node counts moved), then fires
// OnImageCatalogued so matches follow the new package IDs.
func (inv *Inventory) recordSynthetic(ctx context.Context, img model.Image, pkgs []model.Package) error {
	st := inv.o.Store
	stored, ok, err := st.GetImage(ctx, img.Digest)
	if err != nil {
		return err
	}
	recatalogue := !ok || inv.catalogRetry[img.Digest]
	if !recatalogue {
		have, err := st.PackagesForImage(ctx, img.Digest)
		if err != nil {
			return err
		}
		recatalogue = !slices.Equal(packageIDs(have), packageIDs(pkgs))
	}
	if !recatalogue {
		img.CataloguedAt = stored.CataloguedAt
		if reflect.DeepEqual(stored, img) {
			return nil
		}
		return st.UpsertImage(ctx, img)
	}
	if err := st.UpsertImage(ctx, img); err != nil {
		return err
	}
	if err := st.PutSBOM(ctx, img.Digest, nil, pkgs); err != nil {
		return err
	}
	if err := inv.o.Hooks.OnImageCatalogued(ctx, img.Digest); err != nil {
		inv.catalogRetry[img.Digest] = true
		return fmt.Errorf("image %s catalogued: %w", img.Digest, err)
	}
	delete(inv.catalogRetry, img.Digest)
	return nil
}

func packageIDs(pkgs []model.Package) []string {
	ids := make([]string, len(pkgs))
	for i, p := range pkgs {
		ids[i] = p.ID
	}
	sort.Strings(ids)
	return ids
}

// clusterInfo builds the cluster info from the last control-plane version read (or the stored
// one, when Version is nil or has not answered yet) and the kube-proxy DaemonSet, and returns the
// kube-proxy image tag its version was normalised from.
func (inv *Inventory) clusterInfo(ctx context.Context, now time.Time) (model.ClusterInfo, string, error) {
	inv.mu.Lock()
	gv := inv.gitVersion
	inv.mu.Unlock()
	if gv == "" {
		stored, ok, err := inv.o.Store.GetClusterInfo(ctx)
		if err != nil {
			return model.ClusterInfo{}, "", err
		}
		if ok {
			gv = stored.GitVersion
		}
	}
	ci := model.ClusterInfo{Name: inv.o.ClusterName, GitVersion: gv, UpdatedAt: now}
	if v, dist, low, err := NormalizeK8sVersion(gv); err == nil {
		ci.Version, ci.Distribution, ci.LowConfidence = v, dist, low
	}
	kp, tag, err := inv.kubeProxyVersion(ctx)
	if err != nil {
		return model.ClusterInfo{}, "", err
	}
	ci.KubeProxyVersion = kp
	return ci, tag, nil
}

// kubeProxyVersion returns the normalised image tag of the kube-system/kube-proxy DaemonSet and the
// tag itself, or "" for both.
func (inv *Inventory) kubeProxyVersion(ctx context.Context) (version, tag string, err error) {
	ds := &appsv1.DaemonSet{}
	found, err := inv.get(ctx, "kube-system", "kube-proxy", ds)
	if err != nil || !found || len(ds.Spec.Template.Spec.Containers) == 0 {
		return "", "", err
	}
	image := ds.Spec.Template.Spec.Containers[0].Image
	for _, c := range ds.Spec.Template.Spec.Containers {
		if c.Name == "kube-proxy" {
			image = c.Image
		}
	}
	if _, tag, _, err := SplitRef(image); err == nil {
		if v, _, _, err := NormalizeK8sVersion(tag); err == nil {
			return v, tag, nil
		}
	}
	return "", "", nil
}

// refreshVersion reads the control-plane version; a nil Version skips it.
func (inv *Inventory) refreshVersion(ctx context.Context) {
	if inv.o.Version == nil {
		return
	}
	info, err := inv.o.Version.ServerVersion()
	if err != nil {
		logf.FromContext(ctx).WithName("inventory").Error(err, "reading the control-plane version failed")
		return
	}
	inv.mu.Lock()
	inv.gitVersion = info.GitVersion
	inv.mu.Unlock()
}

func nodeModel(n *corev1.Node, now time.Time) model.Node {
	i := n.Status.NodeInfo
	out := model.Node{Name: n.Name, OS: i.OperatingSystem, Arch: i.Architecture, OSImage: i.OSImage,
		KernelVersion: i.KernelVersion, KubeletVersion: i.KubeletVersion, ContainerRuntimeVersion: i.ContainerRuntimeVersion,
		UpdatedAt: now}
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady {
			out.Ready = c.Status == corev1.ConditionTrue
		}
	}
	return out
}

// majorityPlatform returns the most common platform among Ready nodes; ties prefer linux/amd64.
func majorityPlatform(nodes []model.Node) NodePlatform {
	counts := map[NodePlatform]int{}
	for _, n := range nodes {
		if n.Ready && n.OS != "" && n.Arch != "" {
			counts[NodePlatform{OS: n.OS, Arch: n.Arch}]++
		}
	}
	best := NodePlatform{OS: "linux", Arch: "amd64"}
	platforms := make([]NodePlatform, 0, len(counts))
	for p := range counts {
		platforms = append(platforms, p)
	}
	sort.Slice(platforms, func(i, j int) bool { return platforms[i].Key() < platforms[j].Key() })
	for _, p := range platforms {
		if counts[p] > counts[best] {
			best = p
		}
	}
	return best
}
