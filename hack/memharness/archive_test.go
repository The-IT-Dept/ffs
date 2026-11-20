//go:build memharness

package memharness

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/osv-scalibr/semantic"
	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/require"
)

// The image files the archive export reads.
const (
	imageStatus    = "var/lib/dpkg/status"
	imageOSRelease = "etc/os-release"
	imageSources   = "etc/apt/sources.list.d/ubuntu.sources"
)

// debArch is the hosts' architecture, as the docker export runs ubuntuImage.
const debArch = "amd64"

// binaryPackages names the package that installs each of hostBinaries.
var binaryPackages = map[string]string{
	"containerd": "containerd", "containerd-shim-runc-v2": "containerd", "runc": "runc",
}

// downloadOnly are the fields of an archive's package index that describe the .deb rather than the package,
// so dpkg's status file does not have them. Filename is dropped only when the entry is written.
var downloadOnly = []string{
	"Size", "MD5sum", "SHA1", "SHA256", "SHA512", "Description-md5", "Origin", "Bugs", "Task", "Supported",
	"Phased-Update-Percentage",
}

// exportFromArchive writes what the docker export writes under export (status, os-release and bin/<name>),
// without docker:
//   - it reads ubuntuImage's dpkg status, os-release and apt sources from its registry;
//   - it adds serverPackages to that status as `apt-get install --no-install-recommends` does: each package's
//     Pre-Depends and Depends, recursively, at the highest version the image's sources offer (backports and
//     proposed left out, as apt pins them), upgrading installed packages a version constraint or an explicit
//     install needs newer;
//   - it copies hostBinaries out of their packages' .debs.
//
// Its resolver ignores Conflicts and Breaks, and takes the first provider of a virtual package, so the package
// set can differ from apt's by a few packages. The entries it adds have no Conffiles, and their Maintainer is
// the archive's, so the host SBOMs list fewer files than docker's; package identities are the same.
func exportFromArchive(t *testing.T, ctx context.Context, export string) {
	t.Helper()
	start := time.Now()
	files := imageFiles(t, ctx, ubuntuImage, imageStatus, imageOSRelease, imageSources)
	sources, err := aptSources(files[imageSources])
	require.NoError(t, err)
	arch, err := loadArchive(ctx, sources)
	require.NoError(t, err)
	r, err := newResolver(arch, files[imageStatus])
	require.NoError(t, err)
	base := len(r.installed)
	for _, p := range serverPackages {
		require.NoError(t, r.request(p))
	}
	writeFile(t, filepath.Join(export, "status"), r.status())
	writeFile(t, filepath.Join(export, "os-release"), files[imageOSRelease])

	debs := map[string]map[string]string{} // package → path in the .deb → binary name
	for _, b := range hostBinaries {
		pkg, ok := binaryPackages[b.Name]
		require.True(t, ok, "binaryPackages names the package of %s", b.Name)
		if debs[pkg] == nil {
			debs[pkg] = map[string]string{}
		}
		debs[pkg][strings.TrimPrefix(b.Path, "/")] = b.Name
	}
	for pkg, want := range debs {
		p, ok := arch.pkgs[pkg]
		require.True(t, ok, "%s is in the archive", pkg)
		inst, ok := r.installed[pkg]
		require.True(t, ok, "%s is installed", pkg)
		c, err := inst.version.Compare(p.version)
		require.NoError(t, err)
		require.Zero(t, c, "%s is installed at the archive's version", pkg)
		require.NoError(t, extractDeb(ctx, p.uri+"/"+p.stanza.get("Filename"), want, filepath.Join(export, "bin")), pkg)
	}
	t.Logf("resolved %s and %d server packages against %d apt sources: %d packages installed (%d in the image) in %s",
		ubuntuImage, len(serverPackages), len(sources), len(r.installed), base, time.Since(start).Round(time.Second))
}

// imageFiles reads files (paths without a leading slash) from image's linux/amd64 filesystem in its registry,
// following symlinks to regular files of the same base name.
func imageFiles(t *testing.T, ctx context.Context, image string, want ...string) map[string][]byte {
	t.Helper()
	ref, err := name.ParseReference(image)
	require.NoError(t, err)
	img, err := remote.Image(ref, remote.WithContext(ctx), remote.WithPlatform(v1.Platform{OS: "linux", Architecture: debArch}))
	require.NoError(t, err, "pull %s", image)
	rc := mutate.Extract(img)
	defer func() { _ = rc.Close() }()

	bases := map[string]bool{}
	for _, p := range want {
		bases[path.Base(p)] = true
	}
	regular, links := map[string][]byte{}, map[string]string{}
	tr := tar.NewReader(rc)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err, "read %s", image)
		p := strings.TrimPrefix(path.Clean("/"+hdr.Name), "/")
		switch {
		case !bases[path.Base(p)]:
		case hdr.Typeflag == tar.TypeReg:
			b, err := io.ReadAll(io.LimitReader(tr, 64<<20))
			require.NoError(t, err)
			regular[p] = b
		case hdr.Typeflag == tar.TypeSymlink:
			links[p] = hdr.Linkname
		}
	}
	out := map[string][]byte{}
	for _, w := range want {
		p := w
		for range 8 {
			if b, ok := regular[p]; ok {
				out[w] = b
				break
			}
			target, ok := links[p]
			if !ok {
				break
			}
			if path.IsAbs(target) {
				p = strings.TrimPrefix(path.Clean(target), "/")
			} else {
				p = path.Join(path.Dir(p), target)
			}
		}
		require.Contains(t, out, w, "%s has /%s", image, w)
	}
	return out
}

// debField is a field of a deb822 stanza. A multi-line value keeps its continuation lines, each after "\n".
type debField struct{ name, value string }

// debStanza is a deb822 stanza: a dpkg status entry, a package index entry or an apt source.
type debStanza []debField

func (s debStanza) get(name string) string {
	for _, f := range s {
		if strings.EqualFold(f.name, name) {
			return f.value
		}
	}
	return ""
}

func (s debStanza) String() string {
	var b strings.Builder
	for i, f := range s {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(f.name + ":")
		if !strings.HasPrefix(f.value, "\n") {
			b.WriteByte(' ')
		}
		b.WriteString(f.value)
	}
	return b.String()
}

// parseStanzas calls fn with each stanza of a deb822 file.
func parseStanzas(r io.Reader, fn func(debStanza) error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	var cur debStanza
	flush := func() error {
		if len(cur) == 0 {
			return nil
		}
		s := cur
		cur = nil
		return fn(s)
	}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.TrimSpace(line) == "":
			if err := flush(); err != nil {
				return err
			}
		case strings.HasPrefix(line, "#"):
		case line[0] == ' ' || line[0] == '\t':
			if len(cur) == 0 {
				return fmt.Errorf("continuation line outside a field: %q", line)
			}
			cur[len(cur)-1].value += "\n" + line
		default:
			name, value, ok := strings.Cut(line, ":")
			if !ok {
				return fmt.Errorf("not a field: %q", line)
			}
			cur = append(cur, debField{name: name, value: strings.TrimSpace(value)})
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return flush()
}

// aptSource is one suite of an apt source.
type aptSource struct {
	uri, suite string
	components []string
}

// aptSources reads a deb822 apt sources file: its deb sources, over HTTPS, without backports and proposed,
// which apt pins below the release.
func aptSources(b []byte) ([]aptSource, error) {
	var out []aptSource
	err := parseStanzas(bytes.NewReader(b), func(s debStanza) error {
		if !slices.Contains(strings.Fields(s.get("Types")), "deb") || strings.EqualFold(s.get("Enabled"), "no") {
			return nil
		}
		for _, uri := range strings.Fields(s.get("URIs")) {
			uri = strings.TrimSuffix(uri, "/")
			if rest, ok := strings.CutPrefix(uri, "http://"); ok {
				uri = "https://" + rest
			}
			for _, suite := range strings.Fields(s.get("Suites")) {
				if strings.HasSuffix(suite, "-backports") || strings.HasSuffix(suite, "-proposed") {
					continue
				}
				out = append(out, aptSource{uri: uri, suite: suite, components: strings.Fields(s.get("Components"))})
			}
		}
		return nil
	})
	if err == nil && len(out) == 0 {
		err = errors.New("no deb sources")
	}
	return out, err
}

// debPackage is a package's candidate: its index entry, without the downloadOnly fields.
type debPackage struct {
	stanza  debStanza
	version semantic.Version
	uri     string // the archive its Filename is under
}

// archive is what apt's package lists hold for one architecture: each package's candidate, the highest
// version any source offers, and the candidates that provide each virtual package.
type archive struct {
	pkgs     map[string]*debPackage
	provides map[string][]provide
}

// provide is a package's Provides entry: the package, and the version it provides, or "" for none.
type provide struct{ pkg, version string }

// loadArchive reads the debArch package index of every source's components.
func loadArchive(ctx context.Context, sources []aptSource) (*archive, error) {
	a := &archive{pkgs: map[string]*debPackage{}, provides: map[string][]provide{}}
	for _, src := range sources {
		for _, comp := range src.components {
			url := fmt.Sprintf("%s/dists/%s/%s/binary-%s/Packages.gz", src.uri, src.suite, comp, debArch)
			if err := a.load(ctx, src.uri, url); err != nil {
				return nil, fmt.Errorf("%s: %w", url, err)
			}
		}
	}
	for name, p := range a.pkgs {
		for _, alts := range relations(p.stanza.get("Provides")) {
			a.provides[alts[0].name] = append(a.provides[alts[0].name], provide{pkg: name, version: alts[0].version})
		}
	}
	for _, ps := range a.provides {
		slices.SortFunc(ps, func(x, y provide) int { return strings.Compare(x.pkg, y.pkg) })
	}
	return a, nil
}

func (a *archive) load(ctx context.Context, uri, url string) error {
	body, err := httpGet(ctx, url)
	if err != nil {
		return err
	}
	defer func() { _ = body.Close() }()
	zr, err := gzip.NewReader(body)
	if err != nil {
		return err
	}
	return parseStanzas(zr, func(s debStanza) error {
		if arch := s.get("Architecture"); arch != debArch && arch != "all" {
			return nil
		}
		name := s.get("Package")
		v, err := semantic.Parse(s.get("Version"), "Debian")
		if err != nil {
			return fmt.Errorf("%s %s: %w", name, s.get("Version"), err)
		}
		if cur, ok := a.pkgs[name]; ok {
			if c, err := v.Compare(cur.version); err != nil || c <= 0 {
				return err
			}
		}
		s = slices.DeleteFunc(s, func(f debField) bool { return slices.Contains(downloadOnly, f.name) })
		a.pkgs[name] = &debPackage{stanza: s, version: v, uri: uri}
		return nil
	})
}

// relation is one alternative of a dependency: a package, and a version constraint when op is set.
type relation struct{ name, op, version string }

// relations parses a relationship field (Depends, Pre-Depends, Provides): its comma-separated clauses, each
// a list of "|"-separated alternatives. Architecture qualifiers (":any") are dropped.
func relations(field string) [][]relation {
	var out [][]relation
	for _, clause := range strings.Split(strings.ReplaceAll(field, "\n", " "), ",") {
		var alts []relation
		for _, alt := range strings.Split(clause, "|") {
			alt = strings.TrimSpace(alt)
			if alt == "" {
				continue
			}
			pkg, constraint, _ := strings.Cut(alt, "(")
			pkg, _, _ = strings.Cut(strings.TrimSpace(pkg), ":")
			r := relation{name: pkg}
			if constraint = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(constraint), ")")); constraint != "" {
				i := strings.IndexFunc(constraint, func(c rune) bool { return !strings.ContainsRune("<=>", c) })
				if i < 0 {
					i = len(constraint)
				}
				r.op, r.version = constraint[:i], strings.TrimSpace(constraint[i:])
			}
			alts = append(alts, r)
		}
		if len(alts) > 0 {
			out = append(out, alts)
		}
	}
	return out
}

// provides reports whether a Provides entry of version have meets a dependency: an unversioned entry meets
// only an unversioned dependency.
func provides(have, op, want string) (bool, error) {
	switch {
	case op == "":
		return true, nil
	case have == "":
		return false, nil
	}
	v, err := semantic.Parse(have, "Debian")
	if err != nil {
		return false, err
	}
	return satisfies(v, op, want)
}

// satisfies reports whether version have meets the constraint op want; an empty op is no constraint.
func satisfies(have semantic.Version, op, want string) (bool, error) {
	if op == "" {
		return true, nil
	}
	c, err := have.CompareStr(want)
	if err != nil {
		return false, err
	}
	switch op {
	case "<<":
		return c < 0, nil
	case "<=", "<":
		return c <= 0, nil
	case "=":
		return c == 0, nil
	case ">=", ">":
		return c >= 0, nil
	case ">>":
		return c > 0, nil
	}
	return false, fmt.Errorf("unknown version relation %q", op)
}

// installedPackage is a package in the resolver's status: its status entry and version.
type installedPackage struct {
	stanza  debStanza
	version semantic.Version
}

// resolver installs packages from an archive into a dpkg status.
type resolver struct {
	arch      *archive
	installed map[string]installedPackage
	provided  map[string][]string // virtual package → the versions installed packages provide ("" for none)
}

// newResolver starts from the installed packages of a dpkg status file.
func newResolver(arch *archive, status []byte) (*resolver, error) {
	r := &resolver{arch: arch, installed: map[string]installedPackage{}, provided: map[string][]string{}}
	err := parseStanzas(bytes.NewReader(status), func(s debStanza) error {
		if s.get("Status") != "install ok installed" {
			return nil
		}
		v, err := semantic.Parse(s.get("Version"), "Debian")
		if err != nil {
			return fmt.Errorf("%s %s: %w", s.get("Package"), s.get("Version"), err)
		}
		r.mark(s, v)
		return nil
	})
	return r, err
}

func (r *resolver) mark(s debStanza, v semantic.Version) {
	r.installed[s.get("Package")] = installedPackage{stanza: s, version: v}
	for _, alts := range relations(s.get("Provides")) {
		r.provided[alts[0].name] = append(r.provided[alts[0].name], alts[0].version)
	}
}

// request installs a package as `apt-get install` does: its candidate, unless that version is installed.
func (r *resolver) request(name string) error {
	p, ok := r.arch.pkgs[name]
	if !ok {
		return fmt.Errorf("%s is not in the archive", name)
	}
	if cur, ok := r.installed[name]; ok {
		if c, err := p.version.Compare(cur.version); err != nil || c <= 0 {
			return err
		}
	}
	return r.add(name, p)
}

// add installs a package's candidate, then whatever its Pre-Depends and Depends need.
func (r *resolver) add(name string, p *debPackage) error {
	s := make(debStanza, 0, len(p.stanza)+1)
	for _, f := range p.stanza {
		if f.name == "Filename" {
			continue
		}
		s = append(s, f)
		if f.name == "Package" {
			s = append(s, debField{name: "Status", value: "install ok installed"})
		}
	}
	r.mark(s, p.version)
	for _, field := range []string{"Pre-Depends", "Depends"} {
		for _, alts := range relations(p.stanza.get(field)) {
			if err := r.depend(alts); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
	}
	return nil
}

// depend meets one dependency clause: nothing when an installed package or Provides entry meets an
// alternative already, else the first alternative whose candidate meets its constraint, else the first
// candidate whose Provides entry meets one.
func (r *resolver) depend(alts []relation) error {
	for _, d := range alts {
		if cur, ok := r.installed[d.name]; ok {
			if ok, err := satisfies(cur.version, d.op, d.version); err != nil || ok {
				return err
			}
		}
		for _, v := range r.provided[d.name] {
			if ok, err := provides(v, d.op, d.version); err != nil || ok {
				return err
			}
		}
	}
	for _, d := range alts {
		p, ok := r.arch.pkgs[d.name]
		if !ok {
			continue
		}
		if ok, err := satisfies(p.version, d.op, d.version); err != nil {
			return err
		} else if ok {
			return r.add(d.name, p)
		}
	}
	for _, d := range alts {
		for _, p := range r.arch.provides[d.name] {
			if ok, err := provides(p.version, d.op, d.version); err != nil {
				return err
			} else if ok {
				return r.add(p.pkg, r.arch.pkgs[p.pkg])
			}
		}
	}
	return fmt.Errorf("no package meets %v", alts)
}

// status is the resolver's dpkg status file, its entries ordered by package.
func (r *resolver) status() []byte {
	names := make([]string, 0, len(r.installed))
	for n := range r.installed {
		names = append(names, n)
	}
	slices.Sort(names)
	var b strings.Builder
	for _, n := range names {
		b.WriteString(r.installed[n].stanza.String())
		b.WriteString("\n\n")
	}
	return []byte(b.String())
}

// extractDeb downloads a .deb and writes the files of want (path in the package → name) under dir.
func extractDeb(ctx context.Context, url string, want map[string]string, dir string) error {
	body, err := httpGet(ctx, url)
	if err != nil {
		return err
	}
	defer func() { _ = body.Close() }()
	br := bufio.NewReader(body)
	magic := make([]byte, 8)
	if _, err := io.ReadFull(br, magic); err != nil {
		return fmt.Errorf("%s: %w", url, err)
	}
	if string(magic) != "!<arch>\n" {
		return fmt.Errorf("%s is not a .deb", url)
	}
	for {
		// An ar member header: name [0,16), mtime, uid, gid, mode, size [48,58) and "`\n".
		var hdr [60]byte
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			return fmt.Errorf("%s: no data member: %w", url, err)
		}
		member := strings.TrimSuffix(strings.TrimSpace(string(hdr[:16])), "/")
		size, err := strconv.ParseInt(strings.TrimSpace(string(hdr[48:58])), 10, 64)
		if err != nil {
			return fmt.Errorf("%s: member %s: %w", url, member, err)
		}
		if strings.HasPrefix(member, "data.tar") {
			return extractData(member, io.LimitReader(br, size), want, dir)
		}
		if _, err := br.Discard(int(size + size%2)); err != nil {
			return fmt.Errorf("%s: member %s: %w", url, member, err)
		}
	}
}

// extractData writes the files of want from a .deb's data member.
func extractData(member string, r io.Reader, want map[string]string, dir string) error {
	switch ext := path.Ext(member); ext {
	case ".zst":
		zr, err := zstd.NewReader(r)
		if err != nil {
			return err
		}
		defer zr.Close()
		r = zr
	case ".gz":
		zr, err := gzip.NewReader(r)
		if err != nil {
			return err
		}
		r = zr
	case ".tar":
	default:
		return fmt.Errorf("data member %s: unsupported compression %s", member, ext)
	}
	left := maps.Clone(want)
	tr := tar.NewReader(r)
	for len(left) > 0 {
		hdr, err := tr.Next()
		if err != nil {
			return fmt.Errorf("%s: %v not found: %w", member, slices.Sorted(maps.Keys(left)), err)
		}
		p := strings.TrimPrefix(path.Clean("/"+hdr.Name), "/")
		bin, ok := left[p]
		if !ok {
			continue
		}
		if hdr.Typeflag != tar.TypeReg || hdr.Size > 1<<30 {
			return fmt.Errorf("%s: %s is not a regular file under 1 GiB", member, hdr.Name)
		}
		if err := writeStream(filepath.Join(dir, bin), tr, hdr.Size); err != nil {
			return err
		}
		delete(left, p)
	}
	return nil
}

// writeStream writes the next n bytes of r to a new file at p.
func writeStream(p string, r io.Reader, n int64) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	f, err := os.Create(p) //nolint:gosec // G304: a binary's name under the export directory
	if err != nil {
		return err
	}
	if _, err := io.CopyN(f, r, n); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// httpGet fetches url, failing on any status but 200 OK.
func httpGet(ctx context.Context, url string) (io.ReadCloser, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		cancel()
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		cancel()
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return cancelOnClose{ReadCloser: resp.Body, cancel: cancel}, nil
}

// cancelOnClose cancels a request's context when its body is closed.
type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c cancelOnClose) Close() error {
	err := c.ReadCloser.Close()
	c.cancel()
	return err
}
