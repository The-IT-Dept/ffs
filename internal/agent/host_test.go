package agent

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/agentapi/wire"
)

// writeHostFile writes content at the host path rel under root, creating parents.
func writeHostFile(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o750))
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
}

// hostSymlink creates the link rel under root pointing at target, creating parents.
func hostSymlink(t *testing.T, root, rel, target string) {
	t.Helper()
	p := filepath.Join(root, rel)
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o750))
	require.NoError(t, os.Symlink(target, p))
}

// stagedTree lists every path under dir (relative, "/"-joined) with its permission bits, and fails on a symlink.
func stagedTree(t *testing.T, dir string) map[string]fs.FileMode {
	t.Helper()
	out := map[string]fs.FileMode{}
	require.NoError(t, filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		require.NoError(t, err)
		if p == dir {
			return nil
		}
		fi, err := os.Lstat(p)
		require.NoError(t, err)
		require.Zero(t, fi.Mode()&fs.ModeSymlink, "symlink staged at %s", p)
		rel, err := filepath.Rel(dir, p)
		require.NoError(t, err)
		out[filepath.ToSlash(rel)] = fi.Mode().Perm()
		return nil
	}))
	return out
}

// stagedFiles is the regular files of stagedTree.
func stagedFiles(t *testing.T, dir string) []string {
	t.Helper()
	var files []string
	for rel := range stagedTree(t, dir) {
		if fi, err := os.Stat(filepath.Join(dir, rel)); err == nil && fi.Mode().IsRegular() {
			files = append(files, rel)
		}
	}
	return files
}

func TestHostRoot_Resolve(t *testing.T) {
	dir := t.TempDir()
	root := HostRoot(dir)
	writeHostFile(t, dir, "var/lib/rancher/k3s/data/abc/bin/runc", "runc")
	hostSymlink(t, dir, "var/lib/rancher/k3s/data/current", "/var/lib/rancher/k3s/data/abc")
	hostSymlink(t, dir, "var/lib/rancher/k3s/data/prev", "abc")
	hostSymlink(t, dir, "usr/bin/evil", "../../../../../etc/passwd")
	hostSymlink(t, dir, "usr/bin/abs", "/")
	hostSymlink(t, dir, "a", "b")
	hostSymlink(t, dir, "b", "a")

	want := dir + "/var/lib/rancher/k3s/data/abc/bin/runc"
	got, err := root.Resolve("/var/lib/rancher/k3s/data/current/bin/runc")
	require.NoError(t, err)
	require.Equal(t, want, got, "an absolute link target restarts at the host root")
	got, err = root.Resolve("/var/lib/rancher/k3s/data/prev/bin/runc")
	require.NoError(t, err)
	require.Equal(t, want, got, "a relative link target is joined to the link's dir")

	_, err = root.Resolve("/usr/bin/evil")
	require.ErrorIs(t, err, fs.ErrNotExist, "never the real /etc/passwd")
	writeHostFile(t, dir, "etc/passwd", "root:x:0:0")
	got, err = root.Resolve("/usr/bin/evil")
	require.NoError(t, err)
	require.Equal(t, dir+"/etc/passwd", got, ".. is clamped at the host root")

	got, err = root.Resolve("/usr/bin/abs")
	require.NoError(t, err)
	require.Equal(t, dir, got)

	_, err = root.Resolve("/a")
	require.ErrorIs(t, err, syscall.ELOOP)
	require.EqualError(t, err, "resolving /a: too many levels of symbolic links")

	_, err = root.Resolve("/var/lib/rancher/k3s/data/abc/bin/runc/x")
	require.ErrorIs(t, err, fs.ErrNotExist, "a file used as a directory is a missing path")

	for _, p := range []string{"/var/lib/rancher/k3s/data/current/bin/runc", "/usr/bin/evil", "/usr/bin/abs", "/../../usr"} {
		got, err := root.Resolve(p)
		require.NoError(t, err, p)
		require.True(t, strings.HasPrefix(got, dir), "%s resolved outside the host root: %s", p, got)
	}
}

func TestStageHost_Dpkg(t *testing.T) {
	ctx := context.Background()
	host, scratch := t.TempDir(), t.TempDir()
	writeHostFile(t, host, "etc/os-release", "ID=ubuntu\nVERSION_ID=\"26.04\"\n")
	writeHostFile(t, host, "var/lib/dpkg/status", "Package: openssl\n")
	writeHostFile(t, host, "var/lib/dpkg/status.d/base", "Package: base-files\n")
	writeHostFile(t, host, "usr/bin/containerd", "containerd!!")
	writeHostFile(t, host, "usr/bin/kubelet", "kubelet")
	writeHostFile(t, host, "usr/bin/unrelated", "unrelated")

	in, err := StageHost(ctx, HostRoot(host), PathsFor(DistContainerd), scratch+"/host-1", 1<<20)
	require.NoError(t, err)
	require.Equal(t, scratch+"/host-1", in.Dir)
	require.Equal(t, "dpkg", in.PackageDB)
	require.Empty(t, in.Problems)
	require.Equal(t, []wire.Binary{
		{Name: "containerd", Path: "/usr/bin/containerd", Size: 12},
		{Name: "kubelet", Path: "/usr/bin/kubelet", Size: 7},
	}, in.Binaries)

	tree := stagedTree(t, in.Dir)
	require.ElementsMatch(t, []string{"etc/os-release", "var/lib/dpkg/status", "var/lib/dpkg/status.d/base", "usr/bin/containerd",
		"usr/bin/kubelet"}, stagedFiles(t, in.Dir))
	for rel, mode := range tree {
		fi, err := os.Stat(filepath.Join(in.Dir, rel))
		require.NoError(t, err)
		if fi.IsDir() {
			require.Equal(t, fs.FileMode(0o755), mode, rel)
		} else {
			require.Equal(t, fs.FileMode(0o644), mode, rel)
		}
	}
	fi, err := os.Stat(in.Dir)
	require.NoError(t, err)
	require.Equal(t, fs.FileMode(0o755), fi.Mode().Perm())
	b, err := os.ReadFile(filepath.Join(in.Dir, "var/lib/dpkg/status"))
	require.NoError(t, err)
	require.Equal(t, "Package: openssl\n", string(b))

	_, err = StageHost(ctx, HostRoot(host), PathsFor(DistContainerd), scratch+"/host-1", 1<<20)
	require.Error(t, err, "the stage dir must not exist")
	_, err = os.Stat(filepath.Join(in.Dir, "etc/os-release"))
	require.NoError(t, err, "a refused stage leaves the existing dir alone")
}

func TestStageHost_CrioBinary(t *testing.T) {
	host, scratch := t.TempDir(), t.TempDir()
	writeHostFile(t, host, "var/lib/rpm/rpmdb.sqlite", "sqlite")
	writeHostFile(t, host, "usr/bin/crio", "crio-bin")

	in, err := StageHost(context.Background(), HostRoot(host), PathsFor(DistCRIO), scratch+"/host-1", 1<<20)
	require.NoError(t, err)
	require.Equal(t, "rpm", in.PackageDB)
	require.Equal(t, []wire.Binary{{Name: "crio", Path: "/usr/bin/crio", Size: 8}}, in.Binaries)
	require.Empty(t, in.Problems)
}

func TestStageHost_K3sSymlinksStagedOnce(t *testing.T) {
	host, scratch := t.TempDir(), t.TempDir()
	writeHostFile(t, host, "var/lib/dpkg/status", "Package: openssl\n")
	data := "/var/lib/rancher/k3s/data"
	hostSymlink(t, host, data+"/current", data+"/abc")
	writeHostFile(t, host, data+"/abc/bin/k3s", "k3s multi-call")
	hostSymlink(t, host, data+"/abc/bin/containerd", "k3s")
	hostSymlink(t, host, data+"/abc/bin/crictl", "k3s")
	writeHostFile(t, host, data+"/abc/bin/runc", "runc")
	writeHostFile(t, host, data+"/abc/bin/aux/unrelated", "x")
	writeHostFile(t, host, "usr/local/bin/k3s", "k3s installed")

	in, err := StageHost(context.Background(), HostRoot(host), PathsFor(DistK3s), scratch+"/host-1", 1<<20)
	require.NoError(t, err)
	k3s := data + "/abc/bin/k3s"
	require.Equal(t, []wire.Binary{
		{Name: "containerd", Path: k3s, Size: 14},
		{Name: "crictl", Path: k3s, Size: 14},
		{Name: "k3s", Path: "/usr/local/bin/k3s", Size: 13},
		{Name: "k3s", Path: k3s, Size: 14},
		{Name: "runc", Path: data + "/abc/bin/runc", Size: 4},
	}, in.Binaries)
	require.ElementsMatch(t, []string{"var/lib/dpkg/status", "var/lib/rancher/k3s/data/abc/bin/k3s", "var/lib/rancher/k3s/data/abc/bin/runc",
		"usr/local/bin/k3s"}, stagedFiles(t, in.Dir), "the multi-call binary is staged once, as a regular file")
	fi, err := os.Lstat(filepath.Join(in.Dir, k3s))
	require.NoError(t, err)
	require.True(t, fi.Mode().IsRegular())
}

func TestStageHost_RKE2HighestDataDirWithoutLink(t *testing.T) {
	host, scratch := t.TempDir(), t.TempDir()
	writeHostFile(t, host, "var/lib/dpkg/status", "Package: openssl\n")
	writeHostFile(t, host, "var/lib/rancher/rke2/data/v1.30.9-rke2r1-aaa/bin/runc", "old runc")
	writeHostFile(t, host, "var/lib/rancher/rke2/data/v1.31.4-rke2r1-bbb/bin/runc", "new runc")
	writeHostFile(t, host, "var/lib/rancher/rke2/data/v1.9.0-rke2r1-ccc/bin/runc", "older runc")
	writeHostFile(t, host, "var/lib/rancher/rke2/data/zz-not-a-dir", "x")

	in, err := StageHost(context.Background(), HostRoot(host), PathsFor(DistRKE2), scratch+"/host-1", 1<<20)
	require.NoError(t, err)
	require.Equal(t, []wire.Binary{{Name: "runc", Path: "/var/lib/rancher/rke2/data/v1.31.4-rke2r1-bbb/bin/runc", Size: 8}}, in.Binaries)
	require.ElementsMatch(t, []string{"var/lib/dpkg/status", "var/lib/rancher/rke2/data/v1.31.4-rke2r1-bbb/bin/runc"}, stagedFiles(t, in.Dir))
	require.Empty(t, in.Problems)
}

func TestStageHost_RKE2CurrentLinkAfterRollback(t *testing.T) {
	host, scratch := t.TempDir(), t.TempDir()
	writeHostFile(t, host, "var/lib/dpkg/status", "Package: openssl\n")
	writeHostFile(t, host, "var/lib/rancher/rke2/data/v1.30.9-rke2r1-aaa/bin/kubelet", "old kubelet")
	writeHostFile(t, host, "var/lib/rancher/rke2/data/v1.31.4-rke2r1-bbb/bin/kubelet", "new kubelet")
	// Rolled back: the current link names the older data dir, and the newer one stays behind.
	hostSymlink(t, host, "var/lib/rancher/rke2/bin", "/var/lib/rancher/rke2/data/v1.30.9-rke2r1-aaa/bin")

	in, err := StageHost(context.Background(), HostRoot(host), PathsFor(DistRKE2), scratch+"/host-1", 1<<20)
	require.NoError(t, err)
	require.Equal(t, []wire.Binary{{Name: "kubelet", Path: "/var/lib/rancher/rke2/data/v1.30.9-rke2r1-aaa/bin/kubelet", Size: 11}},
		in.Binaries, "the binaries RKE2 runs, not the newest data dir")
}

func TestStageHost_RKE2BinDirMounted(t *testing.T) {
	// In the agent pod the link is mounted, so it shows as the directory it named when the pod started.
	host, scratch := t.TempDir(), t.TempDir()
	writeHostFile(t, host, "var/lib/dpkg/status", "Package: openssl\n")
	writeHostFile(t, host, "var/lib/rancher/rke2/data/v1.31.4-rke2r1-bbb/bin/kubelet", "new kubelet")
	writeHostFile(t, host, "var/lib/rancher/rke2/bin/kubelet", "old kubelet")

	in, err := StageHost(context.Background(), HostRoot(host), PathsFor(DistRKE2), scratch+"/host-1", 1<<20)
	require.NoError(t, err)
	require.Equal(t, []wire.Binary{{Name: "kubelet", Path: "/var/lib/rancher/rke2/bin/kubelet", Size: 11}}, in.Binaries)
}

func TestStageHost_UnreadableEntriesAreSkipped(t *testing.T) {
	host, scratch := t.TempDir(), t.TempDir()
	writeHostFile(t, host, "etc/os-release", "ID=ubuntu\n")
	writeHostFile(t, host, "var/lib/dpkg/status", "Package: openssl\n")
	writeHostFile(t, host, "var/lib/dpkg/status.d", "a file where dpkg keeps a directory") // ENOTDIR when listed
	hostSymlink(t, host, "usr/bin/kubelet", "kubelet")                                     // ELOOP when resolved
	writeHostFile(t, host, "usr/bin/containerd", "containerd")

	in, err := StageHost(context.Background(), HostRoot(host), PathsFor(DistContainerd), scratch+"/host-1", 1<<20)
	require.NoError(t, err, "one bad entry does not stop staging")
	require.Equal(t, "dpkg", in.PackageDB)
	require.Equal(t, []wire.Binary{{Name: "containerd", Path: "/usr/bin/containerd", Size: 10}}, in.Binaries)
	require.Equal(t, []wire.Problem{
		{Code: "scratch", Path: "/var/lib/dpkg/status.d", Detail: "not staged: not a directory"},
		{Code: "scratch", Path: "/usr/bin/kubelet", Detail: "not staged: too many levels of symbolic links"},
	}, in.Problems)
	require.ElementsMatch(t, []string{"etc/os-release", "var/lib/dpkg/status", "usr/bin/containerd"}, stagedFiles(t, in.Dir))
}

func TestStageHost_UnreadableDatabaseIsNotMissing(t *testing.T) {
	host, scratch := t.TempDir(), t.TempDir()
	hostSymlink(t, host, "var/lib/dpkg/status", "status") // the only database, and it cannot be read

	in, err := StageHost(context.Background(), HostRoot(host), PathsFor(DistContainerd), scratch+"/host-1", 1<<20)
	require.NoError(t, err)
	require.Empty(t, in.PackageDB)
	require.Equal(t, []wire.Problem{{Code: "scratch", Path: "/var/lib/dpkg/status", Detail: "not staged: too many levels of symbolic links"}},
		in.Problems, "a database that exists is never reported as no_package_db")
}

func TestStage_ScratchErrorsAreNotHostPermissionProblems(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes to read-only dirs")
	}
	host := t.TempDir()
	writeHostFile(t, host, "etc/os-release", "ID=ubuntu\n")
	dir := filepath.Join(t.TempDir(), "stage")
	require.NoError(t, os.Mkdir(dir, 0o500))       //nolint:gosec // G301: a stage dir the collector cannot write
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // G302: let the test clean up
	s := &stager{root: HostRoot(host), dir: dir, max: 1 << 20, staged: map[string]int64{}}

	_, _, _, err := s.stage("/etc/os-release")
	var se *scratchError
	require.ErrorAs(t, err, &se, "a stage dir that cannot be written stops staging")
	require.ErrorIs(t, err, fs.ErrPermission)
	require.Empty(t, s.problems, "and is not reported as the host denying access")
}
func TestStageHost_NoPackageDatabase(t *testing.T) {
	host, scratch := t.TempDir(), t.TempDir()
	writeHostFile(t, host, "etc/os-release", "ID=talos\n")
	writeHostFile(t, host, "usr/bin/containerd", "containerd")

	in, err := StageHost(context.Background(), HostRoot(host), PathsFor(DistContainerd), scratch+"/host-1", 1<<20)
	require.NoError(t, err)
	require.Empty(t, in.PackageDB)
	require.Equal(t, []wire.Problem{{Code: "no_package_db", Detail: "no dpkg, rpm or apk database found"}}, in.Problems)
}

func TestStageHost_PermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads files whatever their mode")
	}
	host, scratch := t.TempDir(), t.TempDir()
	writeHostFile(t, host, "etc/os-release", "ID=ubuntu\n")
	writeHostFile(t, host, "var/lib/dpkg/status", "Package: openssl\n")
	status := filepath.Join(host, "var/lib/dpkg/status")
	require.NoError(t, os.Chmod(status, 0))
	t.Cleanup(func() { _ = os.Chmod(status, 0o600) })

	in, err := StageHost(context.Background(), HostRoot(host), PathsFor(DistContainerd), scratch+"/host-1", 1<<20)
	require.NoError(t, err)
	require.Empty(t, in.PackageDB)
	require.Equal(t, []wire.Problem{{Code: "permission_denied", Path: "/var/lib/dpkg/status", Detail: "permission denied"}}, in.Problems,
		"a database exists, so there is no no_package_db problem")
	_, err = os.Stat(filepath.Join(in.Dir, "var/lib/dpkg/status"))
	require.ErrorIs(t, err, fs.ErrNotExist)
}

func TestStageHost_MaxBytes(t *testing.T) {
	host, scratch := t.TempDir(), t.TempDir()
	writeHostFile(t, host, "var/lib/dpkg/status", strings.Repeat("s", 40))
	writeHostFile(t, host, "usr/bin/kubelet", strings.Repeat("k", 80))
	writeHostFile(t, host, "usr/bin/runc", strings.Repeat("r", 50))

	in, err := StageHost(context.Background(), HostRoot(host), PathsFor(DistContainerd), scratch+"/host-1", 100)
	require.NoError(t, err)
	require.Equal(t, "dpkg", in.PackageDB)
	require.Equal(t, []wire.Problem{{Code: "scratch", Path: "/usr/bin/kubelet", Detail: "not staged: host inputs exceed 100 bytes"}}, in.Problems)
	require.Equal(t, []wire.Binary{{Name: "runc", Path: "/usr/bin/runc", Size: 50}}, in.Binaries, "a later, smaller file still fits")
	require.ElementsMatch(t, []string{"var/lib/dpkg/status", "usr/bin/runc"}, stagedFiles(t, in.Dir))
}

func TestStageHost_CancelledRemovesDir(t *testing.T) {
	host, scratch := t.TempDir(), t.TempDir()
	writeHostFile(t, host, "etc/os-release", "ID=ubuntu\n")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := StageHost(ctx, HostRoot(host), PathsFor(DistContainerd), scratch+"/host-1", 1<<20)
	require.ErrorIs(t, err, context.Canceled)
	_, err = os.Stat(scratch + "/host-1")
	require.True(t, errors.Is(err, fs.ErrNotExist))
}

func TestStageHost_VersionCompare(t *testing.T) {
	require.Positive(t, versionCompare("v1.31.4-rke2r1-bbb", "v1.30.9-rke2r1-aaa"))
	require.Positive(t, versionCompare("v1.10.0", "v1.9.9"))
	require.Negative(t, versionCompare("v1.9.0", "v1.10.0"))
	require.Positive(t, versionCompare("v1.31.4-b", "v1.31.4-a"))
	require.Negative(t, versionCompare("v01", "v1"), "numerically equal names fall back to string order")
	require.Zero(t, versionCompare("abc", "abc"))
}

func TestKernelReleaseAndBootID(t *testing.T) {
	old := procDir
	t.Cleanup(func() { procDir = old })
	procDir = t.TempDir()
	_, err := KernelRelease()
	require.ErrorIs(t, err, fs.ErrNotExist)
	_, err = BootID()
	require.ErrorIs(t, err, fs.ErrNotExist)

	writeHostFile(t, procDir, "sys/kernel/osrelease", "7.0.0-34-generic\n")
	writeHostFile(t, procDir, "sys/kernel/random/boot_id", "0b5c9a7e-5d1f-4c4e-9d55-2f6b3c1a8e90\n")
	rel, err := KernelRelease()
	require.NoError(t, err)
	require.Equal(t, "7.0.0-34-generic", rel)
	id, err := BootID()
	require.NoError(t, err)
	require.Equal(t, "0b5c9a7e-5d1f-4c4e-9d55-2f6b3c1a8e90", id)
}
