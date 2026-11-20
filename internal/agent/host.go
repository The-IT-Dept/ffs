package agent

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/the-it-dept/ffs/internal/agentapi/wire"
)

// procDir is where KernelRelease and BootID read the kernel's view of the host; tests point it at a fixture tree.
var procDir = "/proc"

// stageMkdir creates a directory in the stage dir; tests make it fail as a full or unwritable scratch volume does.
var stageMkdir = os.Mkdir

// maxSymlinks bounds the links Resolve follows, as the kernel's ELOOP limit does.
const maxSymlinks = 40

// HostRoot is the directory the host's read-only mounts are under: host path P is visible at HostRoot+P.
type HostRoot string

// Resolve returns where hostPath is visible under the host root, following symbolic links as if the process were
// chrooted at r: an absolute link target restarts at the host root and ".." never climbs above it. A missing
// component gives an error wrapping fs.ErrNotExist.
func (r HostRoot) Resolve(hostPath string) (string, error) {
	resolved, err := r.resolve(hostPath)
	if err != nil {
		return "", err
	}
	return r.join(resolved), nil
}

// join returns the container path of a resolved, clean, absolute host path.
func (r HostRoot) join(hostPath string) string {
	base := strings.TrimRight(string(r), "/")
	if hostPath == "/" {
		if base == "" {
			return "/"
		}
		return base
	}
	return base + hostPath
}

// resolve returns the clean, absolute host path hostPath names after following every symbolic link.
func (r HostRoot) resolve(hostPath string) (string, error) {
	cur := "/"
	rest := strings.Split(hostPath, "/")
	links := 0
	for len(rest) > 0 {
		c := rest[0]
		rest = rest[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			cur = path.Dir(cur)
			continue
		}
		next := path.Join(cur, c)
		fi, err := os.Lstat(r.join(next))
		if err != nil {
			if errors.Is(err, syscall.ENOTDIR) {
				return "", fmt.Errorf("resolving %s: %s is not a directory: %w", hostPath, cur, fs.ErrNotExist)
			}
			return "", fmt.Errorf("resolving %s: %w", hostPath, err)
		}
		if fi.Mode()&fs.ModeSymlink == 0 {
			cur = next
			continue
		}
		links++
		if links > maxSymlinks {
			return "", fmt.Errorf("resolving %s: %w", hostPath, syscall.ELOOP)
		}
		target, err := os.Readlink(r.join(next))
		if err != nil {
			return "", fmt.Errorf("resolving %s: %w", hostPath, err)
		}
		if path.IsAbs(target) {
			cur = "/"
		}
		rest = append(strings.Split(target, "/"), rest...)
	}
	return cur, nil
}

// HostInput is what StageHost staged for the cataloguer.
type HostInput struct {
	Dir       string        // the stage dir; host path P was copied to Dir+P (resolved)
	PackageDB string        // the first of dpkg, rpm and apk with a staged database file; "" when none
	Binaries  []wire.Binary // one per (Name, Path) staged, sorted by Name then Path
	Problems  []wire.Problem
}

// packageDBFiles are the database files staged per family, relative to each PackageDBs dir. dpkg's status.d
// entries are listed separately.
var packageDBFiles = map[string][]string{
	"dpkg": {"status"},
	"rpm":  {"rpmdb.sqlite", "Packages", "Packages.db"},
	"apk":  {"installed"},
}

var packageDBOrder = []string{"dpkg", "rpm", "apk"}

// StageHost copies the host's os-release, package databases and known binaries into dir (which must not exist)
// at their resolved host paths, so the non-root cataloguer can read them without host mounts. At most maxBytes
// are staged; a file that does not fit is skipped with a scratch problem. Each host entry stands alone: a
// permission error becomes a permission_denied problem, a missing file is skipped, and any other error reading
// it (a symlink loop, a path through a file) becomes a scratch problem, and staging goes on. Only a failure to
// write the stage dir itself (scratch full or unwritable) or ctx ending is an error; dir is then removed.
func StageHost(ctx context.Context, root HostRoot, paths HostPaths, dir string, maxBytes int64) (HostInput, error) {
	if err := os.Mkdir(dir, 0o755); err != nil { //nolint:gosec // G301: the non-root cataloguer reads staged files
		return HostInput{}, err
	}
	in, err := stageHost(ctx, root, paths, dir, maxBytes)
	if err != nil {
		_ = os.RemoveAll(dir)
		return HostInput{}, err
	}
	return in, nil
}

func stageHost(ctx context.Context, root HostRoot, paths HostPaths, dir string, maxBytes int64) (HostInput, error) {
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // G302: the non-root cataloguer reads staged files
		return HostInput{}, err
	}
	s := &stager{root: root, dir: dir, max: maxBytes, staged: map[string]int64{}}
	in := HostInput{Dir: dir}

	for _, p := range paths.OSRelease {
		if err := ctx.Err(); err != nil {
			return HostInput{}, err
		}
		if _, _, _, err := s.stage(p); err != nil {
			return HostInput{}, err
		}
	}

	// blocked: a database dir or file exists but could not be read, so "no database found" would be wrong.
	found, blocked := false, false
	for _, family := range packageDBOrder {
		for _, d := range paths.PackageDBs[family] {
			files, dirBlocked := s.packageDBFiles(family, d)
			blocked = blocked || dirBlocked
			for _, f := range files {
				if err := ctx.Err(); err != nil {
					return HostInput{}, err
				}
				_, _, st, err := s.stage(f)
				if err != nil {
					return HostInput{}, err
				}
				switch st {
				case stStaged:
					found = true
					if in.PackageDB == "" {
						in.PackageDB = family
					}
				case stOverLimit:
					found = true // present, but over the byte limit
				case stDenied, stUnreadable:
					blocked = true
				}
			}
		}
	}

	seen := map[wire.Binary]bool{}
	for _, d := range paths.BinDirs {
		dirPath, ok := s.binDir(d, paths.Fallbacks[d])
		if !ok {
			continue
		}
		for _, name := range paths.BinaryNames {
			if err := ctx.Err(); err != nil {
				return HostInput{}, err
			}
			resolved, size, st, err := s.stage(path.Join(dirPath, name))
			if err != nil {
				return HostInput{}, err
			}
			if st != stStaged {
				continue
			}
			b := wire.Binary{Name: name, Path: resolved, Size: size}
			if !seen[b] {
				seen[b] = true
				in.Binaries = append(in.Binaries, b)
			}
		}
	}
	slices.SortFunc(in.Binaries, func(a, b wire.Binary) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Path, b.Path))
	})

	if !found && !blocked {
		s.problems = append(s.problems, wire.Problem{Code: wire.ProblemNoPackageDB, Detail: "no dpkg, rpm or apk database found"})
	}
	in.Problems = s.problems
	return in, nil
}

// stageStatus is what happened to one host file.
type stageStatus int

const (
	stSkipped    stageStatus = iota // missing or not a regular file
	stStaged                        // staged now or earlier
	stDenied                        // permission denied (a problem was recorded)
	stOverLimit                     // over the byte limit (a problem was recorded)
	stUnreadable                    // any other error reading it (a problem was recorded)
)

// stager copies host files into the stage dir, counting bytes against the limit.
type stager struct {
	root     HostRoot
	dir      string
	max      int64
	used     int64
	staged   map[string]int64 // resolved host path → size
	problems []wire.Problem
}

// readErr records a host read error on one entry: a permission problem (stDenied), a silent skip when it is
// missing, and otherwise a scratch problem (stUnreadable). The entry is skipped either way; staging goes on.
func (s *stager) readErr(hostPath string, err error) stageStatus {
	switch {
	case errors.Is(err, fs.ErrPermission):
		s.problems = append(s.problems, wire.Problem{Code: wire.ProblemPermissionDenied, Path: hostPath, Detail: "permission denied"})
		return stDenied
	case errors.Is(err, fs.ErrNotExist):
		return stSkipped
	}
	s.unreadable(hostPath, err)
	return stUnreadable
}

// unreadable records a scratch problem for an entry that could not be staged.
func (s *stager) unreadable(hostPath string, err error) {
	s.problems = append(s.problems, wire.Problem{Code: wire.ProblemScratch, Path: hostPath, Detail: "not staged: " + errReason(err)})
}

// errReason is the system's description of err ("too many levels of symbolic links"), without the container
// paths an *fs.PathError carries; err's own text when there is none.
func errReason(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno.Error()
	}
	return err.Error()
}

// scratchError is a failure to write the stage dir: the scratch volume is full or not writable. It stops
// staging, and is never reported as a problem of the host.
type scratchError struct{ err error }

func (e *scratchError) Error() string { return "writing the stage dir: " + e.err.Error() }

func (e *scratchError) Unwrap() error { return e.err }

// stage copies the regular file hostPath names to the stage dir at its resolved host path. It returns that path
// and the size when the file is staged, now or by an earlier call. The error is a *scratchError: only writing
// the stage dir stops staging.
func (s *stager) stage(hostPath string) (string, int64, stageStatus, error) {
	resolved, err := s.root.resolve(hostPath)
	if err != nil {
		return "", 0, s.readErr(hostPath, err), nil
	}
	if size, ok := s.staged[resolved]; ok {
		return resolved, size, stStaged, nil
	}
	src := s.root.join(resolved)
	fi, err := os.Lstat(src)
	if err != nil {
		return "", 0, s.readErr(hostPath, err), nil
	}
	if !fi.Mode().IsRegular() {
		return "", 0, stSkipped, nil
	}
	if s.used+fi.Size() > s.max {
		s.overLimit(hostPath)
		return "", 0, stOverLimit, nil
	}
	n, err := s.copyFile(src, s.dir+resolved, s.max-s.used)
	if err != nil {
		var se *scratchError
		if !errors.As(err, &se) {
			return "", 0, s.readErr(hostPath, err), nil
		}
		if errors.Is(se.err, syscall.ENOTDIR) || errors.Is(se.err, fs.ErrExist) {
			// Two host paths that cannot both be staged (a file where another needs a directory): skip this one.
			s.unreadable(hostPath, se.err)
			return "", 0, stUnreadable, nil
		}
		return "", 0, stSkipped, fmt.Errorf("staging %s: %w", hostPath, err)
	}
	if n < 0 {
		s.overLimit(hostPath) // the file grew past the limit while it was copied
		return "", 0, stOverLimit, nil
	}
	s.used += n
	s.staged[resolved] = n
	return resolved, n, stStaged, nil
}

func (s *stager) overLimit(hostPath string) {
	s.problems = append(s.problems, wire.Problem{Code: wire.ProblemScratch, Path: hostPath,
		Detail: fmt.Sprintf("not staged: host inputs exceed %d bytes", s.max)})
}

// copyFile copies src to dst (0644, parents 0755) and returns the bytes copied, or -1 when src holds more than
// budget bytes (dst is removed). An error writing dst or its parents is a *scratchError; an error reading src
// is returned as it is.
func (s *stager) copyFile(src, dst string, budget int64) (int64, error) {
	in, err := os.Open(src) //nolint:gosec // G304: src is a resolved path under the read-only host root
	if err != nil {
		return 0, err
	}
	defer in.Close() //nolint:errcheck // read-only
	if err := s.mkdirs(path.Dir(dst)); err != nil {
		return 0, &scratchError{err}
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644) //nolint:gosec // G302/G304: the non-root cataloguer reads staged files
	if err != nil {
		return 0, &scratchError{err}
	}
	r := &sourceReader{r: io.LimitReader(in, budget+1)}
	n, err := io.Copy(out, r)
	switch {
	case r.err != nil:
		err = r.err
	case err != nil:
		err = &scratchError{err}
	default:
		if cerr := out.Chmod(0o644); cerr != nil { //nolint:gosec // G302: the non-root cataloguer reads staged files
			err = &scratchError{cerr}
		}
	}
	if cerr := out.Close(); err == nil && cerr != nil {
		err = &scratchError{cerr}
	}
	if err == nil && n > budget {
		n = -1
	}
	if err != nil || n < 0 {
		_ = os.Remove(dst)
	}
	return n, err
}

// sourceReader keeps the error of a read from the host, so a copy can tell it from a write error.
type sourceReader struct {
	r   io.Reader
	err error
}

func (s *sourceReader) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		s.err = err
	}
	return n, err
}

// mkdirs creates d and its missing parents under the stage dir with mode 0755, whatever the umask.
func (s *stager) mkdirs(d string) error {
	if d == s.dir || !strings.HasPrefix(d, s.dir+"/") {
		return nil
	}
	if fi, err := os.Stat(d); err == nil && fi.IsDir() {
		return nil
	}
	if err := s.mkdirs(filepath.Dir(d)); err != nil {
		return err
	}
	if err := stageMkdir(d, 0o755); err != nil && !errors.Is(err, fs.ErrExist) { //nolint:gosec // G301: the non-root cataloguer reads staged files
		return err
	}
	return os.Chmod(d, 0o755) //nolint:gosec // G302: the non-root cataloguer reads staged files
}

// packageDBFiles lists the database files of family in the host dir d. blocked is true when d (or dpkg's
// status.d) exists but could not be read; a problem is then recorded. A missing d gives no files.
func (s *stager) packageDBFiles(family, d string) (files []string, blocked bool) {
	if _, err := s.root.resolve(d); err != nil {
		return nil, s.readErr(d, err) != stSkipped
	}
	for _, f := range packageDBFiles[family] {
		files = append(files, path.Join(d, f))
	}
	if family != "dpkg" {
		return files, false
	}
	statusD := path.Join(d, "status.d")
	resolved, err := s.root.resolve(statusD)
	if err == nil {
		var entries []os.DirEntry
		if entries, err = os.ReadDir(s.root.join(resolved)); err == nil {
			for _, e := range entries {
				files = append(files, path.Join(statusD, e.Name()))
			}
			return files, false
		}
	}
	return files, s.readErr(statusD, err) != stSkipped
}

// binDir is the host bin dir d with its "*" segments expanded. When d is missing and has a fallback, the
// fallback stands in for it: RKE2's bin dir is its link to the current data dir, and only without that link is
// the newest data dir used. ok is false when there is nothing to search, or the dir cannot be searched.
func (s *stager) binDir(d, fallback string) (string, bool) {
	if fallback != "" {
		if _, err := s.root.resolve(d); errors.Is(err, fs.ErrNotExist) {
			d = fallback
		}
	}
	dir, ok := s.expand(d)
	return dir, ok && s.searchable(dir)
}

// searchable reports whether names can be looked up in the host dir d. A dir that exists but cannot be searched
// (permission denied, or a link loop) records one problem, rather than one for each binary name; a missing dir,
// or a file where the dir should be, records none.
func (s *stager) searchable(d string) bool {
	resolved, err := s.root.resolve(d)
	if err == nil {
		// Looking up "." in the dir needs the same search permission as looking up a binary's name in it.
		_, err = os.Lstat(s.root.join(resolved) + "/.")
	}
	switch {
	case err == nil:
		return true
	case errors.Is(err, syscall.ENOTDIR):
		return false // not a dir: there is nothing to search, as when it is missing
	}
	s.readErr(d, err)
	return false
}

// expand replaces each "*" segment of the host dir d by the child directory whose name sorts highest in
// version-aware order. ok is false when a "*" has no child directory or a dir could not be read (a problem is
// recorded unless it is missing).
func (s *stager) expand(d string) (string, bool) {
	if !strings.Contains(d, "*") {
		return d, true
	}
	cur := "/"
	for _, c := range strings.Split(d, "/") {
		if c != "*" {
			cur = path.Join(cur, c)
			continue
		}
		resolved, err := s.root.resolve(cur)
		if err != nil {
			s.readErr(cur, err)
			return "", false
		}
		entries, err := os.ReadDir(s.root.join(resolved))
		if err != nil {
			s.readErr(cur, err)
			return "", false
		}
		best := ""
		for _, e := range entries {
			child, err := s.root.resolve(path.Join(resolved, e.Name()))
			if err != nil {
				continue
			}
			if fi, err := os.Stat(s.root.join(child)); err != nil || !fi.IsDir() {
				continue
			}
			if best == "" || versionCompare(e.Name(), best) > 0 {
				best = e.Name()
			}
		}
		if best == "" {
			return "", false
		}
		cur = path.Join(cur, best)
	}
	return cur, true
}

// versionCompare orders names with numeric runs compared as numbers ("v1.31.4" > "v1.30.9" > "v1.9.0"); names
// that compare equal that way fall back to plain string order.
func versionCompare(a, b string) int {
	ra, rb := runs(a), runs(b)
	for i := 0; i < len(ra) && i < len(rb); i++ {
		x, y := ra[i], rb[i]
		if isDigit(x[0]) && isDigit(y[0]) {
			x, y = strings.TrimLeft(x, "0"), strings.TrimLeft(y, "0")
			if c := cmp.Or(cmp.Compare(len(x), len(y)), cmp.Compare(x, y)); c != 0 {
				return c
			}
			continue
		}
		if c := cmp.Compare(x, y); c != 0 {
			return c
		}
	}
	return cmp.Or(cmp.Compare(len(ra), len(rb)), cmp.Compare(a, b))
}

// runs splits s into maximal runs of digits and non-digits.
func runs(s string) []string {
	var out []string
	start := 0
	for i := 1; i <= len(s); i++ {
		if i == len(s) || isDigit(s[i]) != isDigit(s[start]) {
			out = append(out, s[start:i])
			start = i
		}
	}
	return out
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// KernelRelease returns the running kernel's release from /proc/sys/kernel/osrelease.
func KernelRelease() (string, error) { return readProc("sys/kernel/osrelease") }

// BootID returns the host's boot ID from /proc/sys/kernel/random/boot_id.
func BootID() (string, error) { return readProc("sys/kernel/random/boot_id") }

func readProc(rel string) (string, error) {
	b, err := os.ReadFile(filepath.Join(procDir, rel)) //nolint:gosec // G304: a fixed /proc file
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return "", fmt.Errorf("%s is empty", filepath.Join(procDir, rel))
	}
	return v, nil
}
