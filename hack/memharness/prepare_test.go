//go:build memharness

package memharness

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/agentapi/wire"
	"github.com/the-it-dept/ffs/internal/catalog"
	"github.com/the-it-dept/ffs/internal/feeds"
	"github.com/the-it-dept/ffs/internal/feeds/grypedb"
	"github.com/the-it-dept/ffs/internal/feeds/osv"
	"github.com/the-it-dept/ffs/internal/match/k8s"
	"github.com/the-it-dept/ffs/internal/match/upstream"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/sbom"
	"github.com/the-it-dept/ffs/internal/store"
)

// ubuntuImage is the public image whose package database, with serverPackages installed, is the hosts' dpkg set.
const ubuntuImage = "ubuntu:26.04"

// serverPackages are what a Kubernetes node's Ubuntu server install adds to the base image: remote access,
// networking, storage, container runtime, cloud-init and the usual admin tools. They are installed without
// recommends, so the dependency closure stays that of a minimal server.
var serverPackages = []string{
	"openssh-server", "curl", "wget", "ca-certificates", "gnupg", "iproute2", "iptables", "nftables", "ebtables",
	"ethtool", "conntrack", "socat", "ipset", "ipvsadm", "nfs-common", "open-iscsi", "multipath-tools", "lvm2",
	"cryptsetup", "xfsprogs", "parted", "kmod", "udev", "systemd", "systemd-sysv", "systemd-timesyncd",
	"systemd-resolved", "dbus", "rsyslog", "logrotate", "cron", "sudo", "less", "vim-tiny", "htop", "lsof", "strace",
	"tcpdump", "net-tools", "bind9-dnsutils", "iputils-ping", "traceroute", "netplan.io", "cloud-init", "apparmor",
	"auditd", "unattended-upgrades", "python3", "openssl", "git", "jq", "zstd", "xz-utils", "bash-completion",
	"containerd", "runc", "snapd", "rsync",
}

// hostBinaries are the agent's known host binaries (agent.BinaryNames) that the packages above install. The
// agent stages them for the go-module cataloguer, so the host SBOM carries their Go modules.
var hostBinaries = []wire.Binary{
	{Name: "containerd", Path: "/usr/bin/containerd"},
	{Name: "containerd-shim-runc-v2", Path: "/usr/bin/containerd-shim-runc-v2"},
	{Name: "runc", Path: "/usr/sbin/runc"},
}

// kernelVersion is the package version of the running kernel's packages (kernelRelease).
const kernelVersion = "7.0.0-34.34"

// kernelStanzas are the dpkg status entries of the running kernel's package family, as an Ubuntu 26.04
// server has them installed: image, modules, extra modules, headers and their metapackages. The per-release
// packages are built from the source package linux.
func kernelStanzas() []string {
	const abi = "7.0.0-34"
	entry := func(name, arch, source, section, desc string, size int) string {
		return strings.Join([]string{
			"Package: " + name,
			"Status: install ok installed",
			"Priority: optional",
			"Section: " + section,
			fmt.Sprintf("Installed-Size: %d", size),
			"Maintainer: Ubuntu Kernel Team <kernel-team@lists.ubuntu.com>",
			"Architecture: " + arch,
			"Source: " + source,
			"Version: " + kernelVersion,
			"Description: " + desc,
		}, "\n")
	}
	return []string{
		entry("linux-image-"+abi+"-generic", "amd64", "linux", "kernel", "Linux kernel image for version 7.0.0 on 64 bit x86 SMP", 15692),
		entry("linux-modules-"+abi+"-generic", "amd64", "linux", "kernel", "Linux kernel extra modules for version 7.0.0 on 64 bit x86 SMP", 112456),
		entry("linux-modules-extra-"+abi+"-generic", "amd64", "linux", "kernel", "Linux kernel extra modules for version 7.0.0 on 64 bit x86 SMP", 418372),
		entry("linux-headers-"+abi+"-generic", "amd64", "linux", "devel", "Linux kernel headers for version 7.0.0 on 64 bit x86 SMP", 31244),
		entry("linux-headers-"+abi, "all", "linux", "devel", "Header files related to Linux kernel version 7.0.0", 96512),
		entry("linux-generic", "amd64", "linux-meta", "kernel", "Complete Generic Linux kernel and headers", 17),
		entry("linux-image-generic", "amd64", "linux-meta", "kernel", "Generic Linux kernel image", 17),
		entry("linux-headers-generic", "amd64", "linux-meta", "kernel", "Generic Linux kernel headers", 17),
	}
}

// TestPrepare builds the harness's inputs under the work directory, each step once (a marker file records
// it): the advisory store and Grype DB (prepareAdvisories), then the host SBOMs (prepareHosts).
func TestPrepare(t *testing.T) {
	dir := workDir()
	require.NoError(t, os.MkdirAll(dir, 0o750))
	prepareAdvisories(t, dir)
	prepareHosts(t, dir)
}

// prepareAdvisories downloads the latest Grype DB and syncs the OSV feed into a fresh store at
// <dir>/advisories.db, through the feeds' own code and the production engine as their handler. Its OSV cache
// is what a long-running install holds for Ubuntu and Debian hosts: every record those buckets changed within
// the window (envWindow), plus the Go and GIT buckets the feed always loads.
func prepareAdvisories(t *testing.T, dir string) {
	marker := filepath.Join(dir, "advisories.ok")
	if _, err := os.Stat(marker); err == nil {
		t.Logf("advisory store already prepared (%s)", marker)
		return
	}
	ctx := context.Background()
	dbPath := filepath.Join(dir, advisoriesDB)
	for _, p := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		require.NoError(t, os.RemoveAll(p))
	}
	st, err := store.Open(ctx, dbPath)
	require.NoError(t, err)
	defer func() { require.NoError(t, st.Close()) }()
	cfg := harnessConfig(dir)
	log := stepLogger(t)
	eng, _ := newEngine(cfg, st, log.WithName("engine"))

	start := time.Now()
	gfeed := grypedb.New(grypedb.Options{Config: cfg.Feeds.GrypeDB.Feed(), DataDir: cfg.DataDir, Store: st, Handler: eng.OnGrypeDB})
	require.NoError(t, gfeed.Sync(logr.NewContext(ctx, log.WithName("grypedb"))))
	path, built, ok, err := gfeed.Current(ctx)
	require.NoError(t, err)
	require.True(t, ok, "the Grype DB is installed")
	t.Logf("Grype DB built %s installed at %s in %s", built.Format(time.RFC3339), path, time.Since(start).Round(time.Second))

	// The feed polls the buckets of the ecosystems in the store: a placeholder image with one Ubuntu 26.04 and
	// one Debian 13 package puts Ubuntu and Debian in use. It is pruned once the feed has synced.
	placeholder := "sha256:" + strings.Repeat("0", 64)
	pkgs := []model.Package{
		{ImageDigest: placeholder, Ecosystem: "deb", Name: "base-files", Version: "14ubuntu1", SourceName: "base-files",
			Distro: &model.Distro{ID: "ubuntu", VersionID: "26.04"}, Arch: "amd64"},
		{ImageDigest: placeholder, Ecosystem: "deb", Name: "base-files", Version: "13.8", SourceName: "base-files",
			Distro: &model.Distro{ID: "debian", VersionID: "13"}, Arch: "amd64"},
	}
	for i := range pkgs {
		pkgs[i].ID = model.PackageID(placeholder, pkgs[i])
	}
	require.NoError(t, st.UpsertImage(ctx, model.Image{Digest: placeholder, Repo: "example.com/placeholder", Status: model.ImagePending}))
	require.NoError(t, st.PutSBOM(ctx, placeholder, []byte(`{}`), pkgs))

	window := osvWindow(t)
	if window > 0 {
		// Without a watermark the first poll reads the last 72 hours; a watermark at the window's start reads
		// the window instead (the osv feed's meta key wm.<bucket>).
		fs, err := st.FeedState(ctx, feeds.NameOSV)
		require.NoError(t, err)
		if fs.Meta == nil {
			fs.Meta = map[string]string{}
		}
		from := time.Now().UTC().Add(-window).Format(time.RFC3339Nano)
		fs.Meta["wm.Ubuntu"], fs.Meta["wm.Debian"] = from, from
		require.NoError(t, st.PutFeedState(ctx, fs))
	}
	start = time.Now()
	ofeed := osv.New(osv.Options{Config: cfg.Feeds.OSV, Store: st, Handler: eng.OnOSVRecords, DataDir: cfg.DataDir,
		GitRepos: append(upstream.Repos(), k8s.Repo)})
	require.NoError(t, ofeed.Sync(logr.NewContext(ctx, log.WithName("osv"))))
	t.Logf("OSV feed synced in %s", time.Since(start).Round(time.Second))

	now := time.Now()
	_, err = st.PruneImages(ctx, now, 0)
	require.NoError(t, err)
	n, err := st.PruneImages(ctx, now.Add(time.Second), 0)
	require.NoError(t, err)
	require.Equal(t, 1, n, "the placeholder image is pruned")

	var summary strings.Builder
	fmt.Fprintf(&summary, "grype DB built %s\nosv window %s\n", built.Format(time.RFC3339), window)
	for _, b := range []string{"Ubuntu", "Debian", osv.BucketGo, osv.BucketGIT} {
		ids, err := st.OSVRecordIDs(ctx, b)
		require.NoError(t, err)
		fmt.Fprintf(&summary, "osv bucket %s: %d records\n", b, len(ids))
	}
	linux, err := st.OSVRecordIDsByName(ctx, "Ubuntu", []string{"linux"})
	require.NoError(t, err)
	fmt.Fprintf(&summary, "Ubuntu records indexed under linux: %d\n", len(linux))
	t.Log(summary.String())
	require.NoError(t, os.WriteFile(marker, []byte(summary.String()), 0o600))
}

// prepareHosts writes the five group host SBOMs to <dir>/hosts/group-<n>.json, as the node agent's cataloguer
// produces them: the dpkg database of ubuntu:26.04 with serverPackages installed (exportWithDocker, or
// exportFromArchive without docker; see hostsSource), the running kernel's package family, and the containerd
// and runc binaries, staged like the agent stages a host and catalogued in process with the agent's host-dir
// cataloguer. Group n leaves out 5+2n packages, chosen differently for each group, so the groups' fingerprints
// differ.
func prepareHosts(t *testing.T, dir string) {
	hostsDir := filepath.Join(dir, "hosts")
	marker := filepath.Join(hostsDir, "hosts.ok")
	if _, err := os.Stat(marker); err == nil {
		t.Logf("host SBOMs already prepared (%s)", marker)
		return
	}
	ctx := context.Background()
	require.NoError(t, os.RemoveAll(hostsDir))
	export := filepath.Join(hostsDir, "export")
	require.NoError(t, os.MkdirAll(filepath.Join(export, "bin"), 0o750))

	source := hostsSource(t, ctx)
	if source == sourceDocker {
		exportWithDocker(t, ctx, export)
	} else {
		exportFromArchive(t, ctx, export)
	}

	status, err := os.ReadFile(filepath.Join(export, "status")) //nolint:gosec // G304: the export directory
	require.NoError(t, err)
	base := installedStanzas(status)
	t.Logf("%d installed dpkg packages, plus %d kernel packages", len(base), len(kernelStanzas()))
	osRelease, err := os.ReadFile(filepath.Join(export, "os-release")) //nolint:gosec // G304: the export directory
	require.NoError(t, err)

	names := make([]string, 0, len(base))
	for _, s := range base {
		names = append(names, stanzaPackage(s))
	}
	slices.Sort(names)
	var groups []hostGroup
	for g := range groupCount {
		left := leftOut(names, g)
		stage := filepath.Join(hostsDir, fmt.Sprintf("stage-%d", g))
		var kept []string
		for _, s := range base {
			if !slices.Contains(left, stanzaPackage(s)) {
				kept = append(kept, s)
			}
		}
		kept = append(kept, kernelStanzas()...)
		writeFile(t, filepath.Join(stage, "etc", "os-release"), osRelease)
		writeFile(t, filepath.Join(stage, "var", "lib", "dpkg", "status"), []byte(strings.Join(kept, "\n\n")+"\n"))
		for _, b := range hostBinaries {
			bin, err := os.ReadFile(filepath.Join(export, "bin", b.Name)) //nolint:gosec // G304: the export directory
			require.NoError(t, err)
			writeFile(t, filepath.Join(stage, filepath.FromSlash(b.Path)), bin)
		}
		resp, err := catalog.Catalog(ctx, sbom.CatalogRequest{Source: sbom.CatalogSourceHostDir, Path: stage})
		require.NoError(t, err)
		writeFile(t, hostPath(dir, g), resp.SyftJSON)
		require.NoError(t, os.RemoveAll(stage))
		groups = append(groups, hostGroup{Group: g, Source: source, LeftOut: left, Packages: len(kept),
			SyftJSONBytes: len(resp.SyftJSON)})
		t.Logf("group %d: %d dpkg packages (left out %v), syft-json %d bytes", g, len(kept), left, len(resp.SyftJSON))
	}
	require.NoError(t, os.RemoveAll(export))
	b, err := json.MarshalIndent(groups, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(marker, b, 0o600))
}

// The ways prepareHosts gets the hosts' dpkg database and binaries (FFS_MEMHARNESS_HOSTS).
const (
	sourceDocker  = "docker"
	sourceArchive = "archive"
)

// hostsSource picks how prepareHosts gets the hosts' packages: FFS_MEMHARNESS_HOSTS when set, else docker
// when its daemon answers, else the archive.
func hostsSource(t *testing.T, ctx context.Context) string {
	switch v := os.Getenv(envHosts); v {
	case sourceDocker, sourceArchive:
		return v
	case "":
	default:
		t.Fatalf("%s=%q: want %s or %s", envHosts, v, sourceDocker, sourceArchive)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "docker", "info").Run(); err != nil {
		t.Logf("docker is unavailable (%v): resolving the hosts' packages from the Ubuntu archive", err)
		return sourceArchive
	}
	return sourceDocker
}

// exportWithDocker installs serverPackages in ubuntuImage with apt, and copies its dpkg status, os-release
// and hostBinaries to export (status, os-release, bin/<name>).
func exportWithDocker(t *testing.T, ctx context.Context, export string) {
	t.Helper()
	var copyBins []string
	for _, b := range hostBinaries {
		copyBins = append(copyBins, fmt.Sprintf("cp %s /out/bin/%s", b.Path, b.Name))
	}
	script := "set -e; apt-get update -qq >/dev/null; apt-get install -y -qq --no-install-recommends " +
		strings.Join(serverPackages, " ") + " >/dev/null 2>&1; cp /var/lib/dpkg/status /out/status; " +
		"cp /etc/os-release /out/os-release; " + strings.Join(copyBins, "; ")
	start := time.Now()
	//nolint:gosec // G204: docker with the harness's own script and export directory
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "--platform", "linux/"+debArch, "-e", "DEBIAN_FRONTEND=noninteractive",
		"-v", export+":/out", ubuntuImage, "sh", "-c", script)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "docker run %s: %s", ubuntuImage, out)
	t.Logf("exported the dpkg database of %s with %d server packages in %s", ubuntuImage, len(serverPackages),
		time.Since(start).Round(time.Second))
}

// hostGroup describes one generated group host SBOM.
type hostGroup struct {
	Group         int      `json:"group"`
	Source        string   `json:"source"`
	LeftOut       []string `json:"leftOut"`
	Packages      int      `json:"packages"`
	SyftJSONBytes int      `json:"syftJSONBytes"`
}

// installedStanzas returns the entries of a dpkg status file whose packages are installed.
func installedStanzas(status []byte) []string {
	var out []string
	for _, s := range strings.Split(string(bytes.TrimSpace(status)), "\n\n") {
		if strings.Contains(s, "\nStatus: install ok installed") {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}

// stanzaPackage is the Package field of a dpkg status entry.
func stanzaPackage(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if name, ok := strings.CutPrefix(line, "Package: "); ok {
			return name
		}
	}
	return ""
}

// leftOut picks the 5+2g packages of names group g does without, spread over the sorted names and
// different for every group.
func leftOut(names []string, g int) []string {
	var out []string
	for k := 0; len(out) < 5+2*g && k < len(names); k++ {
		n := names[(g*37+k*53)%len(names)]
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

// writeFile writes a file under the work directory, creating its directory.
//
//nolint:gosec // G703: paths under the work directory, which the harness's operator chooses
func writeFile(t *testing.T, path string, b []byte) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
	require.NoError(t, os.WriteFile(path, b, 0o600))
}

// resetDir makes dir, a directory under the work directory, empty.
//
//nolint:gosec // G703: as writeFile
func resetDir(t *testing.T, dir string) {
	t.Helper()
	require.NoError(t, os.RemoveAll(dir))
	require.NoError(t, os.MkdirAll(dir, 0o750))
}
