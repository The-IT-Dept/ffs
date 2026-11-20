package agentapi

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	syftsbom "github.com/anchore/syft/syft/sbom"
	corev1 "k8s.io/api/core/v1"

	"github.com/the-it-dept/ffs/internal/agentapi/wire"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/nodegroup"
	"github.com/the-it-dept/ffs/internal/sbom"
)

// pendingDigest names a host SBOM while it is normalised, before its fingerprint is known.
const pendingDigest = "nodegroup:pending"

// Coverage gap details (copy).
const (
	detailNoPackageDatabase = "no package database (image-based OS)"
	detailContentStore      = "no containerd content store on this node; side-loaded images cannot be catalogued from it"
	detailBlockedFmt        = "node agent cannot read %s: permission denied"
)

// Media types of image indexes in a content store.
var indexMediaTypes = []string{"application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"}

// hostPrep is a host SBOM made ready to store: only the running kernel's packages, upstream Go module names,
// its fingerprint and its group's description. Preparing writes nothing.
type hostPrep struct {
	SyftJSON    []byte
	Fingerprint string
	Group       model.NodeGroup
	Split       nodegroup.KernelSplit
}

// prepareHost decodes the report's host SBOM, rewrites forked Go modules to their upstream names, removes the
// packages of kernels that are not running (and their relationships), and fingerprints the host.
func prepareHost(r *wire.Report, n *corev1.Node, now time.Time) (hostPrep, error) {
	doc, err := sbom.DecodeSyftJSON(r.Host.SyftJSON)
	if err != nil {
		return hostPrep{}, err
	}
	if doc.Artifacts.Packages == nil {
		doc.Artifacts.Packages = pkg.NewCollection()
	}
	canonicaliseModules(doc)
	pkgs, _ := sbom.Normalize(pendingDigest, doc)
	split := nodegroup.SplitKernels(pkgs, r.KernelRelease)
	removeKernels(doc, split.Other)
	b, err := sbom.EncodeSyftJSON(doc)
	if err != nil {
		return hostPrep{}, fmt.Errorf("encoding the host SBOM: %w", err)
	}

	info := n.Status.NodeInfo
	fp := nodegroup.Fingerprint(nodegroup.FingerprintInput{Packages: split.Running, Kernel: split.Kernel,
		KernelRelease: r.KernelRelease, RuntimeVersion: info.ContainerRuntimeVersion})
	var distro *model.Distro
	if ld := doc.Artifacts.LinuxDistribution; ld != nil {
		distro = &model.Distro{ID: ld.ID, VersionID: ld.VersionID, Codename: ld.VersionCodename}
	}
	name := nodegroup.GroupName(distro, info.OSImage, r.KernelRelease)
	return hostPrep{
		SyftJSON:    b,
		Fingerprint: fp,
		Split:       split,
		Group: model.NodeGroup{
			ID: fp, Kind: model.NodeGroupAgent, Name: name, Label: nodegroup.GroupLabel(name, fp), Digest: nodegroup.GroupDigest(fp),
			Distro: distro, OSImage: info.OSImage, KernelRelease: r.KernelRelease, ContainerRuntimeVersion: info.ContainerRuntimeVersion,
			KubeletVersion: info.KubeletVersion, Arch: r.Arch, Kernel: split.Kernel, Binaries: binariesOf(doc, r.Host.Binaries),
			PackageDB: r.Host.PackageDB, PackageCount: len(split.Running), FirstSeen: now, LastSeen: now,
		},
	}, nil
}

// canonicaliseModules rewrites each go-module package through nodegroup.CanonicalModule, keeping its artifact
// ID, so Grype and module suppression see the upstream names of forks (k3s builds on k3s-io forks).
func canonicaliseModules(doc *syftsbom.SBOM) {
	for _, p := range doc.Artifacts.Packages.Sorted(pkg.GoModulePkg) {
		name, version := nodegroup.CanonicalModule(p.Name, p.Version)
		if name == p.Name && version == p.Version {
			continue
		}
		q := p // keeps p's artifact ID
		q.Name, q.Version, q.PURL = name, version, "pkg:golang/"+name+"@"+version
		doc.Artifacts.Packages.Delete(p.ID())
		doc.Artifacts.Packages.Add(q)
	}
}

// removeKernels deletes the packages of kernels that are not running from doc, with every relationship that
// names one of them.
func removeKernels(doc *syftsbom.SBOM, other []model.Package) {
	if len(other) == 0 {
		return
	}
	gone := make(map[artifact.ID]bool, len(other))
	for _, p := range other {
		id := artifact.ID(p.SyftID)
		gone[id] = true
		doc.Artifacts.Packages.Delete(id) // one at a time: Delete stops at the first unknown ID
	}
	doc.Relationships = slices.DeleteFunc(doc.Relationships, func(rel artifact.Relationship) bool {
		return (rel.From != nil && gone[rel.From.ID()]) || (rel.To != nil && gone[rel.To.ID()])
	})
}

// binariesOf matches each reported binary to the go-module package of its main module at the binary's path.
// A binary with no match keeps an empty Module and Version. The result is sorted by Name, then Path.
func binariesOf(doc *syftsbom.SBOM, bins []wire.Binary) []model.NodeBinary {
	if len(bins) == 0 {
		return nil
	}
	type mainModule struct{ module, version string }
	byPath := map[string]mainModule{}
	if doc.Artifacts.Packages != nil {
		for _, p := range doc.Artifacts.Packages.Sorted(pkg.GoModulePkg) {
			locs := p.Locations.ToSlice()
			if len(locs) == 0 {
				continue
			}
			mm, ok := mainModuleOf(p.Metadata)
			if !ok {
				continue
			}
			if canon, _ := nodegroup.CanonicalModule(mm, ""); canon != p.Name {
				continue
			}
			if _, seen := byPath[locs[0].RealPath]; !seen {
				byPath[locs[0].RealPath] = mainModule{module: p.Name, version: p.Version}
			}
		}
	}
	out := make([]model.NodeBinary, 0, len(bins))
	for _, b := range bins {
		m := byPath[b.Path]
		out = append(out, model.NodeBinary{Name: b.Name, Path: b.Path, Module: m.module, Version: m.version})
	}
	slices.SortFunc(out, func(a, b model.NodeBinary) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Path, b.Path))
	})
	return out
}

func mainModuleOf(meta any) (string, bool) {
	switch m := meta.(type) {
	case pkg.GolangBinaryBuildinfoEntry:
		return m.MainModule, m.MainModule != ""
	case *pkg.GolangBinaryBuildinfoEntry:
		return m.MainModule, m != nil && m.MainModule != ""
	}
	return "", false
}

// coverageOf derives a report's coverage gaps, de-duplicated and sorted by code and detail. A report without
// Images keeps the stored content-store gap.
func coverageOf(r *wire.Report, stored []model.NodeCoverageGap) []model.NodeCoverageGap {
	var gaps []model.NodeCoverageGap
	denied := false
	for _, p := range r.Problems {
		switch p.Code {
		case wire.ProblemPermissionDenied:
			denied = true
			gaps = append(gaps, model.NodeCoverageGap{Code: model.GapNodeAgentBlocked, Detail: fmt.Sprintf(detailBlockedFmt, p.Path)})
		case wire.ProblemNoPackageDB:
			gaps = append(gaps, model.NodeCoverageGap{Code: model.GapNoPackageDatabase, Detail: detailNoPackageDatabase})
		case wire.ProblemContentStore:
			gaps = append(gaps, model.NodeCoverageGap{Code: model.GapContentStoreUnreadable, Detail: detailContentStore})
		}
	}
	if r.Host != nil && r.Host.PackageDB == "" && !denied {
		// SELinux-denied databases are not an image-based OS.
		gaps = append(gaps, model.NodeCoverageGap{Code: model.GapNoPackageDatabase, Detail: detailNoPackageDatabase})
	}
	switch {
	case r.Images != nil && !r.Images.ContentStore:
		gaps = append(gaps, model.NodeCoverageGap{Code: model.GapContentStoreUnreadable, Detail: detailContentStore})
	case r.Images == nil:
		for _, g := range stored {
			if g.Code == model.GapContentStoreUnreadable {
				gaps = append(gaps, g)
			}
		}
	}
	slices.SortFunc(gaps, func(a, b model.NodeCoverageGap) int {
		return cmp.Or(cmp.Compare(a.Code, b.Code), cmp.Compare(a.Detail, b.Detail))
	})
	return slices.Compact(gaps)
}

// problemText is a collection problem as nodes_agent stores it.
func problemText(p wire.Problem) string {
	if p.Path == "" {
		return p.Detail
	}
	return p.Path + ": " + p.Detail
}

// nodeImages merges the content-store scan with node.status.images. A status entry joins the rows of its
// "@sha256:" names (Source "both") or becomes a status-only row; an entry with no digest name has no key and is
// skipped. Rows are sorted by digest.
func nodeImages(imgs *wire.Images, status []corev1.ContainerImage) []model.NodeImage {
	rows := map[string]*model.NodeImage{}
	if imgs != nil {
		for _, ci := range imgs.Digests {
			kind := "manifest"
			if slices.Contains(indexMediaTypes, ci.MediaType) {
				kind = "index"
			}
			rows[ci.Digest] = &model.NodeImage{Digest: ci.Digest, ConfigDigest: ci.ConfigDigest, Kind: kind, SizeBytes: ci.Size,
				Complete: ci.Complete, Source: "content-store"}
		}
	}
	for _, entry := range status {
		for _, d := range statusDigests(entry.Names) {
			row, ok := rows[d]
			switch {
			case !ok:
				rows[d] = &model.NodeImage{Digest: d, Kind: "manifest", Names: slices.Clone(entry.Names), SizeBytes: entry.SizeBytes,
					Source: "status"}
			case row.Source == "content-store":
				row.Source = "both"
				fallthrough
			default:
				row.Names = append(row.Names, entry.Names...)
			}
		}
	}
	out := make([]model.NodeImage, 0, len(rows))
	for _, row := range rows {
		slices.Sort(row.Names)
		row.Names = slices.Compact(row.Names)
		out = append(out, *row)
	}
	slices.SortFunc(out, func(a, b model.NodeImage) int { return cmp.Compare(a.Digest, b.Digest) })
	return out
}

// statusDigests returns the distinct sha256 digests of "<repo>@sha256:<hex>" names, in order.
func statusDigests(names []string) []string {
	var out []string
	for _, n := range names {
		_, hex, ok := strings.Cut(n, "@sha256:")
		if !ok || hex == "" {
			continue
		}
		if d := "sha256:" + hex; !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	return out
}
