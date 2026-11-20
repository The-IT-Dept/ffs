package webtest

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"time"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/registry"
	"github.com/the-it-dept/ffs/internal/store"
)

// ScaleSize is the shape of a Scale fixture. OpenFindings counts every open finding, the
// control-plane ones included.
type ScaleSize struct {
	Namespaces, Workloads, Images, PackagesPerImage int
	OpenFindings, Excepted, Resolved                int
	Suggestions, ExposedWorkloads                   int
}

// DefaultScale is the cluster the API latency gate measures (spec G8): 25,000 open findings over
// 300 workloads.
var DefaultScale = ScaleSize{Namespaces: 20, Workloads: 300, Images: 120, PackagesPerImage: 400, OpenFindings: 25000,
	Excepted: 2500, Resolved: 5000, Suggestions: 40, ExposedWorkloads: 60}

// scaleBatch is the number of findings written per ApplyFindings.
const scaleBatch = 2000

// Images of a Scale fixture that are not catalogued: the last scaleUnresolvable images are
// unresolvable for lack of credentials and the scalePending before them are pending. Image 0, the
// first workload's, is always catalogued.
const (
	scaleUnresolvable = 3
	scalePending      = 5
)

// scaleImageStatus is the status of image i of a fixture with images images.
func scaleImageStatus(i, images int) model.ImageStatus {
	switch {
	case i > 0 && i >= images-scaleUnresolvable:
		return model.ImageUnresolvable
	case i > 0 && i >= images-scaleUnresolvable-scalePending:
		return model.ImagePending
	}
	return model.ImageCatalogued
}

// scaleWorkloadImages returns the images workload i runs, in container order: image i%Images, and
// for every third workload also image 7i%Images.
func scaleWorkloadImages(i int, n ScaleSize) []int {
	images := []int{i % n.Images}
	if i%3 == 2 {
		images = append(images, 7*i%n.Images)
	}
	return images
}

// scaleBearer is a workload that carries findings, and the image they are on.
type scaleBearer struct{ workload, image int }

// scaleBearers returns the workloads that carry findings, in order: every workload that runs a
// catalogued image, with the first one it runs. A workload whose images are all pending or
// unresolvable has no SBOM to match, so it carries none. Workload 0 always carries findings.
func scaleBearers(n ScaleSize) []scaleBearer {
	var out []scaleBearer
	for w := range n.Workloads {
		for _, i := range scaleWorkloadImages(w, n) {
			if scaleImageStatus(i, n.Images) == model.ImageCatalogued {
				out = append(out, scaleBearer{workload: w, image: i})
				break
			}
		}
	}
	return out
}

// Scale opens a store at path and seeds a deterministic cluster of n's size: the cluster-level
// owners and their findings, n.Workloads Deployments over n.Namespaces namespaces and n.Images
// images, n.OpenFindings/8 advisories, and the open, excepted and resolved findings, transitions and
// patch suggestions over them. Every random choice comes from one seeded generator, so two calls
// with the same n write the same rows.
func Scale(ctx context.Context, path string, n ScaleSize) (*Fixture, error) {
	if n.Namespaces < 1 || n.Workloads < 1 || n.Images < 1 || n.PackagesPerImage < 1 || n.OpenFindings < 16 {
		return nil, errors.New("webtest: scale needs a namespace, a workload, an image, a package and 16 open findings")
	}
	bearers := scaleBearers(n)
	if n.OpenFindings-controlPlaneFindings+n.Excepted+n.Resolved > len(bearers)*(n.OpenFindings/8) {
		return nil, errors.New("webtest: scale has more findings than pairs of an advisory and a workload with a catalogued image")
	}
	st, err := store.Open(ctx, path)
	if err != nil {
		return nil, err
	}
	dbPaths.Store(st, path)
	f := &Fixture{Store: st, Pods: PodCounts{}}
	s := &scaler{f: f, n: n, bearers: bearers, rng: rand.New(rand.NewPCG(1, 2)), ts: map[int]model.Transition{}} //nolint:gosec // G404: a fixed seed makes the fixture deterministic
	if err := s.seed(ctx); err != nil {
		return nil, errors.Join(fmt.Errorf("webtest: scale: %w", err), f.Close())
	}
	return f, nil
}

// scaler seeds one Scale fixture.
type scaler struct {
	f       *Fixture
	n       ScaleSize
	bearers []scaleBearer // the workloads that carry findings, from scaleBearers
	rng     *rand.Rand

	owners     []model.Owner    // the workloads, by index
	images     []model.Image    // by index
	advisories []model.Advisory // by index
	findings   []model.Finding
	ts         map[int]model.Transition // creation transitions, by index in findings
}

func (s *scaler) seed(ctx context.Context) error {
	s.f.seedConfig()
	for _, step := range []func(context.Context) error{
		s.f.seedLifecycle, s.seedBase, s.seedClusterLevel, s.seedImages, s.seedWorkloads, s.seedAdvisories,
		s.seedFindings, s.seedSuggestions,
	} {
		if err := step(ctx); err != nil {
			return err
		}
	}
	return nil
}

// seedBase writes fresh feeds, ten worker nodes and the cluster version.
func (s *scaler) seedBase(ctx context.Context) error {
	for _, name := range []string{"osv", "kev", "eol"} {
		at := Now.Add(-10 * time.Minute)
		if err := s.f.Store.PutFeedState(ctx, store.FeedState{Name: name, LastSuccess: at, LastAttempt: at}); err != nil {
			return err
		}
	}
	nodes := make([]model.Node, 10)
	for i := range nodes {
		nodes[i] = smallNode(fmt.Sprintf("worker-%02d", i), kernelWorker)
	}
	if err := s.f.Store.ReplaceNodes(ctx, nodes); err != nil {
		return err
	}
	return s.f.Store.PutClusterInfo(ctx, model.ClusterInfo{Name: ClusterName, GitVersion: "v1.34.2", Version: "1.34.2", UpdatedAt: Now})
}

// seedClusterLevel writes the Cluster and ContainerRuntime owners with their synthetic images, as
// Small does. Their findings are written with the rest.
func (s *scaler) seedClusterLevel(ctx context.Context) error {
	for _, o := range []model.Owner{
		{Ref: Cluster, UpdatedAt: Now,
			Containers: []model.ContainerUse{{Name: "kubernetes", Kind: model.ContainerRegular, ImageRef: "v1.34.2", Repo: "kubernetes", Digest: digestK8s}}},
		{Ref: Runtime, UpdatedAt: Now,
			Containers: []model.ContainerUse{{Name: "containerd", Kind: model.ContainerRegular, ImageRef: "containerd://2.2.1", Repo: "containerd", Digest: digestRuntime}}},
	} {
		if err := s.f.Store.UpsertOwner(ctx, o); err != nil {
			return err
		}
	}
	for _, img := range []struct {
		digest, repo string
		pkg          model.Package
	}{
		{digestK8s, "kubernetes", model.Package{Ecosystem: "kubernetes", Name: "kubernetes", Version: "1.34.2"}},
		{digestRuntime, "containerd", model.Package{Ecosystem: "containerd", Name: "containerd", Version: "2.2.1"}},
	} {
		if err := s.f.Store.UpsertImage(ctx, model.Image{Digest: img.digest, Repo: img.repo, Status: model.ImageCatalogued,
			Source: "inventory", CataloguedAt: Now}); err != nil {
			return err
		}
		if err := s.f.Store.PutSBOM(ctx, img.digest, nil, []model.Package{img.pkg}); err != nil {
			return err
		}
	}
	return nil
}

// scaleDigest is the digest of image i of a Scale fixture.
func scaleDigest(i int) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "image-%d", i))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// scaleEcosystem is the ecosystem of package k of every Scale image.
func scaleEcosystem(k int) string {
	switch k % 10 {
	case 6, 7:
		return "npm"
	case 8:
		return "go-module"
	case 9:
		return "python"
	}
	return "deb"
}

func scalePackage(k int) model.Package {
	p := model.Package{Ecosystem: scaleEcosystem(k), Name: fmt.Sprintf("pkg-%d", k), Version: fmt.Sprintf("1.%d.0", k%20)}
	if p.Ecosystem == "deb" {
		p.Distro, p.Arch = debian12, "amd64"
	}
	return p
}

// seedImages writes n.Images images: catalogued from a registry, except that every 20th is
// attestation-sourced, the last ones are unresolvable or pending, and every 10th carries
// unattributed executables. Each catalogued image holds n.PackagesPerImage packages.
func (s *scaler) seedImages(ctx context.Context) error {
	pkgs := make([]model.Package, s.n.PackagesPerImage)
	for k := range pkgs {
		pkgs[k] = scalePackage(k)
	}
	s.images = make([]model.Image, s.n.Images)
	for i := range s.images {
		repo := fmt.Sprintf("ghcr.io/example/img-%d", i)
		img := model.Image{Digest: scaleDigest(i), Repo: repo, Platform: "linux/amd64", Status: model.ImageCatalogued,
			Source: "registry", CataloguedAt: Now}
		switch scaleImageStatus(i, s.n.Images) {
		case model.ImageUnresolvable:
			img = model.Image{Digest: img.Digest, Repo: repo, Status: model.ImageUnresolvable,
				StatusReason: fmt.Sprintf(registry.ReasonUnauthorized, repo)}
		case model.ImagePending:
			img = model.Image{Digest: img.Digest, Repo: repo, Status: model.ImagePending}
		default:
			if i%20 == 19 {
				img.Source = "attestation"
			}
			if i%10 == 9 {
				img.Coverage = model.Coverage{UnattributedELF: 3, Notes: []string{"3 executables not attributed to any package"}}
			}
		}
		s.images[i] = img
		if err := s.f.Store.UpsertImage(ctx, img); err != nil {
			return err
		}
		if img.Status != model.ImageCatalogued {
			continue
		}
		if err := s.f.Store.PutSBOM(ctx, img.Digest, nil, pkgs); err != nil {
			return err
		}
	}
	return nil
}

// seedWorkloads writes n.Workloads Deployments, each running the images scaleWorkloadImages gives
// it. The first n.ExposedWorkloads are exposed: every tenth of them through its own LoadBalancer
// Service, the rest through one of four public Gateways. Every fifteenth workload also has an
// internal Ingress, every 25th is privileged and every 30th has a powerful service account.
func (s *scaler) seedWorkloads(ctx context.Context) error {
	s.owners = make([]model.Owner, s.n.Workloads)
	for i := range s.owners {
		ns, name := fmt.Sprintf("ns-%02d", i%s.n.Namespaces), fmt.Sprintf("app-%03d", i)
		ref := model.OwnerRef{Kind: "Deployment", Namespace: ns, Name: name}
		use := func(cname string, img model.Image) model.ContainerUse {
			return container(cname, model.ContainerRegular, img.Repo+":1.0.0", img.Repo, img.Digest)
		}
		o := model.Owner{Ref: ref, ServiceAccount: name, UpdatedAt: Now}
		names := []string{"app", "helper"}
		for c, img := range scaleWorkloadImages(i, s.n) {
			o.Containers = append(o.Containers, use(names[c], s.images[img]))
		}
		o.Context = s.workloadContext(i, ns, name)
		s.owners[i] = o
		s.f.Pods[ref.Key()] = 1 + i%3
		if err := s.f.Store.UpsertOwner(ctx, o); err != nil {
			return err
		}
	}
	return nil
}

func (s *scaler) workloadContext(i int, ns, name string) model.WorkloadContext {
	var c model.WorkloadContext
	ref, svc := ns+"/"+name, ns+"/"+name+":8080"
	if i < s.n.ExposedWorkloads {
		if i%10 == 9 {
			c.Exposure = append(c.Exposure, model.ExposureEdge{Entry: model.EntryLoadBalancer, EntryName: ref, Service: ref,
				Path: "Service " + ref + " type LoadBalancer"})
		} else {
			gw, route := fmt.Sprintf("gateway/public-%d", i%4), "HTTPRoute "+ref
			c.Exposure = append(c.Exposure, model.ExposureEdge{Entry: model.EntryGateway, EntryName: gw, Listener: "https",
				Hostname: name + ".example.com", Route: route, Service: svc, Path: route + " on Gateway " + gw})
		}
	}
	if i%15 == 14 {
		c.Exposure = append(c.Exposure, model.ExposureEdge{Entry: model.EntryIngress, EntryName: "internal",
			Hostname: name + ".internal.example.com", Route: "Ingress " + ref, Service: svc, Internal: true})
	}
	slices.SortFunc(c.Exposure, func(a, b model.ExposureEdge) int { return strings.Compare(string(a.Entry), string(b.Entry)) })
	for _, e := range c.Exposure {
		if !e.Internal {
			c.Exposed = true
			c.ExposurePaths = append(c.ExposurePaths, e.Path)
		}
	}
	if i%25 == 24 {
		c.Privileged, c.PrivilegeReasons = true, []string{"container app is privileged"}
	}
	if i%30 == 29 {
		c.PowerfulSA, c.SAReasons = true, []string{"can read Secrets in namespace " + ns}
	}
	return c
}

// seedAdvisories writes n.OpenFindings/8 advisories: 2% in CISA KEV, EPSS uniform in [0, 0.6).
func (s *scaler) seedAdvisories(ctx context.Context) error {
	severities := []model.Severity{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow}
	s.advisories = make([]model.Advisory, s.n.OpenFindings/8)
	for a := range s.advisories {
		adv := model.Advisory{ID: fmt.Sprintf("CVE-2026-1%05d", a), Title: fmt.Sprintf("Flaw %d in pkg-%d", a, a%s.n.PackagesPerImage),
			Published: Now.Add(-time.Duration(a%365) * 24 * time.Hour), Observed: Now, CNASeverity: severities[s.rng.IntN(len(severities))]}
		if s.rng.Float64() < 0.02 {
			added := Now.Add(-30 * 24 * time.Hour)
			adv.KEVAdded = &added
		}
		adv.EPSS = s.rng.Float64() * 0.6
		adv.EPSSPercentile = adv.EPSS / 0.6
		s.advisories[a] = adv
		if err := s.f.Store.UpsertAdvisory(ctx, adv); err != nil {
			return err
		}
	}
	return nil
}

// priorityDraw is urgent 3%, high 17%, medium 40% and low 40%.
func (s *scaler) priorityDraw() model.Priority {
	switch r := s.rng.Float64(); {
	case r < 0.03:
		return model.PriorityUrgent
	case r < 0.20:
		return model.PriorityHigh
	case r < 0.60:
		return model.PriorityMedium
	}
	return model.PriorityLow
}

// fixDraw is rebuild 30%, package 30%, none 30% and won't fix 10%.
func (s *scaler) fixDraw() model.FixKind {
	switch r := s.rng.Float64(); {
	case r < 0.3:
		return model.FixKindRebuild
	case r < 0.6:
		return model.FixKindPackage
	case r < 0.9:
		return model.FixKindNone
	}
	return model.FixKindWontFix
}

var scaleSeverity = map[model.Priority]model.Severity{model.PriorityUrgent: model.SeverityCritical,
	model.PriorityHigh: model.SeverityHigh, model.PriorityMedium: model.SeverityMedium, model.PriorityLow: model.SeverityLow}

// controlPlaneFindings is the number of open findings on the cluster-level owners.
const controlPlaneFindings = 2

// seedFindings writes the control-plane findings, then finding k for k from 0: open, then
// n.Excepted excepted and n.Resolved resolved ones. Finding k belongs to bearer k%len(bearers) and
// advisory (k/len(bearers))%Advisories, on the bearer's first catalogued image, so no two share a key
// and none is on an image without an SBOM. Every tenth finding has a creation transition.
func (s *scaler) seedFindings(ctx context.Context) error {
	s.controlPlane()
	open := s.n.OpenFindings - controlPlaneFindings
	for k := range open + s.n.Excepted + s.n.Resolved {
		state := model.StateOpen
		switch {
		case k >= open+s.n.Excepted:
			state = model.StateResolved
		case k >= open:
			state = model.StateExcepted
		}
		s.finding(k, state)
	}
	for start := 0; start < len(s.findings); start += scaleBatch {
		end := min(start+scaleBatch, len(s.findings))
		var ts []model.Transition
		for i := start; i < end; i++ {
			if t, ok := s.ts[i]; ok {
				ts = append(ts, t)
			}
		}
		if err := s.f.Store.ApplyFindings(ctx, s.findings[start:end], ts); err != nil {
			return err
		}
	}
	return nil
}

// controlPlane adds one open finding on the Cluster owner and one on the ContainerRuntime owner,
// as Small has.
func (s *scaler) controlPlane() {
	last := len(s.advisories) - 1
	for _, c := range []struct {
		owner     model.OwnerRef
		repo, eco string
		digest    string
		from, to  string
		advisory  string
		priority  model.Priority
	}{
		{Cluster, "kubernetes", "kubernetes", digestK8s, "1.34.2", "1.34.3", s.advisories[last].ID, model.PriorityHigh},
		{Runtime, "containerd", "containerd", digestRuntime, "2.2.1", "2.2.2", s.advisories[last-1].ID, model.PriorityMedium},
	} {
		s.findings = append(s.findings, model.Finding{
			Fingerprint: model.FindingFingerprint(ClusterName, c.owner, c.repo, c.advisory), Owner: c.owner, ImageRepo: c.repo,
			AdvisoryID: c.advisory, Packages: []model.FindingPackage{{Name: c.repo, Ecosystem: c.eco, Installed: c.from, Fixed: []string{c.to}}},
			Digests: []string{c.digest}, Severity: scaleSeverity[c.priority], FixState: model.FixFixed, FixAvailable: true,
			Priority: c.priority, State: model.StateOpen, Observed: Now, Matched: Now, LastSeen: Now,
			Fix: packageFix(c.eco, c.repo, c.from, c.to),
		})
	}
}

// finding adds finding k in state.
func (s *scaler) finding(k int, state model.FindingState) {
	b := s.bearers[k%len(s.bearers)]
	o := s.owners[b.workload]
	adv := s.advisories[(k/len(s.bearers))%len(s.advisories)]
	img := s.images[b.image]
	priority, fix := s.priorityDraw(), s.fixDraw()
	p := s.rng.IntN(s.n.PackagesPerImage)
	if fix == model.FixKindRebuild {
		p -= p % 10 // a distro package: only those are fixed by a rebuild
		p += s.rng.IntN(6)
		p = min(p, s.n.PackagesPerImage-1)
		if scaleEcosystem(p) != "deb" {
			fix = model.FixKindPackage
		}
	}
	pkg := scalePackage(p)
	fixed := fmt.Sprintf("1.%d.1", p%20)
	fp := model.FindingPackage{Name: pkg.Name, Ecosystem: pkg.Ecosystem, Installed: pkg.Version}
	f := model.Finding{
		Fingerprint: model.FindingFingerprint(ClusterName, o.Ref, img.Repo, adv.ID), Owner: o.Ref, ImageRepo: img.Repo,
		AdvisoryID: adv.ID, Digests: []string{img.Digest}, Severity: scaleSeverity[priority], SeveritySource: "ghsa",
		Priority: priority, State: state, Published: adv.Published, Observed: Now, Matched: Now, LastSeen: Now,
		Signals: model.FindingSignals{Exposed: o.Context.Exposed, Privileged: o.Context.Privileged, PowerfulSA: o.Context.PowerfulSA,
			KEV: adv.KEVAdded != nil, EPSS: adv.EPSS, EPSSElevated: adv.EPSS >= s.f.Config.Priority.EPSSBump},
	}
	if pkg.Ecosystem == "deb" {
		f.SeveritySource = "debian"
	}
	switch fix {
	case model.FixKindRebuild:
		fp.Fixed = []string{fixed}
		f.FixState, f.FixAvailable, f.Fix = model.FixFixed, true, rebuildFix(debian12)
	case model.FixKindPackage:
		fp.Fixed = []string{fixed}
		f.FixState, f.FixAvailable, f.Fix = model.FixFixed, true, packageFix(pkg.Ecosystem, pkg.Name, pkg.Version, fixed)
	case model.FixKindWontFix:
		f.FixState, f.Fix = model.FixWontFix, wontFix
	default:
		f.FixState, f.Fix = model.FixNotFixed, noFix
	}
	f.Packages = []model.FindingPackage{fp}
	if f.Signals.KEV {
		f.Reasons = append(f.Reasons, "actively exploited (CISA KEV, added "+adv.KEVAdded.Format(time.DateOnly)+")")
	}
	if o.Context.Exposed {
		f.Reasons = append(f.Reasons, "exposed via "+o.Context.ExposurePaths[0])
	}
	switch state {
	case model.StateExcepted:
		f.ExceptedBy = o.Ref.Namespace + "/accept-risk"
	case model.StateResolved:
		at := Now.Add(-time.Duration(s.rng.Float64() * float64(60*24*time.Hour)))
		f.ResolvedAt = &at
	}
	if k%10 == 9 {
		s.ts[len(s.findings)] = model.Transition{Fingerprint: f.Fingerprint, Owner: f.Owner, AdvisoryID: f.AdvisoryID,
			ToState: model.StateOpen, FromPriority: model.PriorityNone, ToPriority: priority, Trigger: model.TriggerNewAdvisory,
			At: Now.Add(-time.Duration(k%720) * time.Hour)}
	}
	s.findings = append(s.findings, f)
}

// seedSuggestions writes a patch suggestion for each of the first n.Suggestions workloads that carry
// findings, on the image they are on, fixing that workload's first five advisories.
func (s *scaler) seedSuggestions(ctx context.Context) error {
	for _, b := range s.bearers[:min(s.n.Suggestions, len(s.bearers))] {
		o := s.owners[b.workload]
		repo := s.images[b.image].Repo
		var (
			ids   []string
			fixes = map[model.Priority]int{}
		)
		for _, f := range s.findings {
			if f.Owner != o.Ref || len(ids) == 5 {
				continue
			}
			ids = append(ids, f.AdvisoryID)
			if f.State == model.StateOpen {
				fixes[f.Priority]++
			}
		}
		slices.SortFunc(ids, cmp.Compare)
		if err := s.f.Store.PutSuggestion(ctx, o.Ref.Key(), model.Suggestion{Repo: repo, FromTag: "1.0.0", ToTag: "1.0.1",
			Tier: model.TierPatch, Fixes: fixes, FixedIDs: ids, ComputedAt: Now}, nil); err != nil {
			return err
		}
	}
	return nil
}
