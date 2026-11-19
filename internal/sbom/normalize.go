package sbom

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	syftsbom "github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"

	"github.com/the-it-dept/ffs/internal/model"
)

// unattributedSuffix ends the unknowns entry syft's unknowns-labeler adds to an executable that no
// package claims.
const unattributedSuffix = "no package identified in executable file"

// distroTypes are the package types installed by the distribution's package manager; only they
// carry the image's Linux distribution.
var distroTypes = map[pkg.Type]bool{
	pkg.DebPkg:     true,
	pkg.RpmPkg:     true,
	pkg.ApkPkg:     true,
	pkg.AlpmPkg:    true,
	pkg.PortagePkg: true,
}

// Normalize turns a syft SBOM for the platform manifest digest into ffs package tuples, in syft's
// sorted package order, plus the image's coverage.
func Normalize(digest string, doc *syftsbom.SBOM) ([]model.Package, model.Coverage) {
	cov := CoverageOf(doc)
	if doc.Artifacts.Packages == nil {
		return nil, cov
	}
	var distro *model.Distro
	if r := doc.Artifacts.LinuxDistribution; r != nil {
		distro = &model.Distro{ID: r.ID, VersionID: r.VersionID, Codename: r.VersionCodename}
	}

	sorted := doc.Artifacts.Packages.Sorted()
	out := make([]model.Package, 0, len(sorted))
	for _, p := range sorted {
		mp := model.Package{
			ImageDigest: digest,
			Ecosystem:   string(p.Type),
			Name:        p.Name,
			Version:     p.Version,
			PURL:        p.PURL,
			GoStdlib:    p.Type == pkg.GoModulePkg && p.Name == "stdlib",
			SyftID:      string(p.ID()),
		}
		if distro != nil && distroTypes[p.Type] {
			d := *distro
			mp.Distro = &d
		}
		for _, c := range p.CPEs {
			mp.CPEs = append(mp.CPEs, c.Attributes.String())
		}
		if locs := p.Locations.ToSlice(); len(locs) > 0 {
			mp.Path, mp.Layer = locs[0].RealPath, locs[0].FileSystemID
		}
		applyMetadata(&mp, p)
		mp.ID = model.PackageID(digest, mp)
		out = append(out, mp)
	}
	return out, cov
}

// applyMetadata fills the source package, epoch, architecture and classifier from the package's
// type-specific metadata.
func applyMetadata(mp *model.Package, p pkg.Package) {
	switch m := p.Metadata.(type) {
	case pkg.DpkgDBEntry:
		name, version := m.Source, m.SourceVersion
		// dpkg writes "Source: name (version)" when the source version differs from the binary's.
		if i := strings.Index(name, " ("); i >= 0 && strings.HasSuffix(name, ")") {
			if version == "" {
				version = name[i+2 : len(name)-1]
			}
			name = name[:i]
		}
		if name = strings.TrimSpace(name); name == "" {
			name = p.Name
		}
		if version == "" {
			version = p.Version
		}
		mp.SourceName, mp.SourceVersion = name, version
		mp.Arch = m.Architecture
		mp.Epoch = debEpoch(p.Version)
	case pkg.ApkDBEntry:
		mp.SourceName, mp.SourceVersion = m.OriginPackage, p.Version
		mp.Arch = m.Architecture
	case pkg.RpmDBEntry:
		mp.SourceName, mp.SourceVersion = SourceRPMName(m.SourceRpm)
		mp.Arch = m.Arch
		if m.Epoch != nil {
			mp.Epoch = strconv.Itoa(*m.Epoch)
		}
	case pkg.BinarySignature:
		if len(m.Matches) > 0 {
			mp.Classifier = m.Matches[0].Classifier
		}
	}
}

// debEpoch returns the numeric epoch prefix of a Debian version ("1:2.3-4" → "1"), or "".
func debEpoch(version string) string {
	e, _, ok := strings.Cut(version, ":")
	if !ok || e == "" {
		return ""
	}
	if _, err := strconv.ParseUint(e, 10, 64); err != nil {
		return ""
	}
	return e
}

// SourceRPMName splits a source RPM file name into its package name and version-release:
// "openssl-3.0.7-27.el9.src.rpm" → ("openssl", "3.0.7-27.el9"). A name that does not have the
// name-version-release form gives ("", "").
func SourceRPMName(srpm string) (name, version string) {
	s := strings.TrimSuffix(srpm, ".rpm")
	s = strings.TrimSuffix(strings.TrimSuffix(s, ".src"), ".nosrc")
	rel := strings.LastIndexByte(s, '-')
	if rel <= 0 {
		return "", ""
	}
	ver := strings.LastIndexByte(s[:rel], '-')
	if ver <= 0 || rel-ver < 2 || rel == len(s)-1 {
		return "", ""
	}
	return s[:ver], s[ver+1:]
}

// UnattributedELF returns, sorted, the coordinates of ELF executables that syft's unknowns-labeler
// found no package for.
func UnattributedELF(doc *syftsbom.SBOM) []file.Coordinates {
	var out []file.Coordinates
	for c, entries := range doc.Artifacts.Unknowns {
		if doc.Artifacts.Executables[c].Format != file.ELF {
			continue
		}
		if slices.ContainsFunc(entries, func(e string) bool { return strings.HasSuffix(e, unattributedSuffix) }) {
			out = append(out, c)
		}
	}
	slices.SortFunc(out, func(a, b file.Coordinates) int {
		return cmp.Or(strings.Compare(a.RealPath, b.RealPath), strings.Compare(a.FileSystemID, b.FileSystemID))
	})
	return out
}

// CoverageOf counts what the SBOM could not attribute: ELF executables no package claims, and Rust
// binaries the cataloguer marked as built without cargo-auditable.
func CoverageOf(doc *syftsbom.SBOM) model.Coverage {
	var cov model.Coverage
	cov.UnattributedELF = len(UnattributedELF(doc))
	for _, entries := range doc.Artifacts.Unknowns {
		if slices.Contains(entries, UnknownRustNoAuditable) {
			cov.RustWithoutAuditable++
		}
	}
	if cov.UnattributedELF > 0 {
		cov.Notes = append(cov.Notes, fmt.Sprintf("%d executables not attributed to any package", cov.UnattributedELF))
	}
	if cov.RustWithoutAuditable > 0 {
		cov.Notes = append(cov.Notes, fmt.Sprintf("%d Rust binaries built without cargo-auditable", cov.RustWithoutAuditable))
	}
	return cov
}

// ConfigUser returns the User from the image config recorded in the SBOM's source, or "" when the
// image sets none or the source is not an image.
func ConfigUser(doc *syftsbom.SBOM) string {
	var raw []byte
	switch m := doc.Source.Metadata.(type) {
	case source.ImageMetadata:
		raw = m.RawConfig
	case *source.ImageMetadata:
		if m != nil {
			raw = m.RawConfig
		}
	}
	if len(raw) == 0 {
		return ""
	}
	var cfg struct{ Config struct{ User string } }
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return ""
	}
	return cfg.Config.User
}
