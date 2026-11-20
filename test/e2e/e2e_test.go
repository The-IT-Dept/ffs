//go:build e2e

// Package e2e runs ffs end to end on a kind cluster (or, with FFS_E2E_KUBECONFIG, an existing k3s
// cluster): a fixture registry holds a known-vulnerable workload, fixture feeds publish its
// advisories, and a webhook receiver checks the alerts and their signatures. Run it with make e2e.
package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	"github.com/the-it-dept/ffs/api/v1alpha1"
	"github.com/the-it-dept/ffs/internal/feeds/grypedb/grypedbtest"
	"github.com/the-it-dept/ffs/internal/web"
	"github.com/the-it-dept/ffs/test/e2e/webhookrx"
)

const (
	eventPrefix   = "au.theitdept.ffs."
	typeDigest    = eventPrefix + "digest.v1"
	typeDetected  = eventPrefix + "finding.detected.v1"
	typeEscalated = eventPrefix + "finding.escalated.v1"
	typeResolved  = eventPrefix + "finding.resolved.v1"

	cveDebian = "CVE-2026-90001" // Debian source package "example", fixed in 1.0-2
	cvePHP    = "CVE-2026-90002" // php 8.3 before 8.3.12, in CISA KEV

	findingDebian = "deployment-app-cve-2026-90001"
	findingPHP    = "deployment-app-cve-2026-90002"

	kevPath = "/kev/known_exploited_vulnerabilities.json"
)

// TestMain connects to the cluster. The fixtures and the ffs install are set up at the start of
// TestE2E, which owns their cleanup and failure dumps.
func TestMain(m *testing.M) {
	if err := connect(); err != nil {
		fmt.Fprintln(os.Stderr, "e2e:", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// suite is the state the ordered subtests share.
type suite struct {
	env        env
	feeds      *feedServer
	rx         *webhookrx.Receiver
	rxURL      string
	secret     string
	appRepo    string
	values     map[string]any // the chart values installed; agent-disabled upgrades with them
	api        string         // base URL of the current step's port-forward
	agentGroup string         // ID of the agent node group (node-group sets it)
	grypeFirst string         // path of the first Grype DB archive, published before the install
	t7, t9     time.Time
}

func TestE2E(t *testing.T) {
	s := setup(t)
	for _, step := range []struct {
		name string
		fn   func(*testing.T)
	}{
		{"baseline", s.baseline},
		{"catalogued", s.catalogued},
		{"grypedb-update", s.grypeDBUpdate},
		{"ui-loads", s.uiLoads},
		{"agent-ready", s.agentReady},
		{"node-group", s.nodeGroup},
		{"host-finding", s.hostFinding},
		{"sideloaded", s.sideloaded},
		{"detected", s.detected},
		{"exposed", s.exposed},
		{"kev-immediate", s.kevImmediate},
		{"tenant-cannot-except-urgent", s.tenantCannotExceptUrgent},
		{"admin-exception-silences", s.adminExceptionSilences},
		{"not-running", s.notRunning},
		{"resolved", s.resolved},
		{"agent-disabled", s.agentDisabled},
		{"hygiene", s.hygiene},
	} {
		if !t.Run(step.name, step.fn) {
			t.FailNow()
		}
	}
}

// setup starts the feed server and webhook receiver, pushes the app image and installs ffs.
func setup(t *testing.T) *suite {
	s := &suite{env: loadEnv(t)}
	s.feeds = startFeedServer(t)

	key := make([]byte, 32)
	_, _ = rand.Read(key)
	s.secret = "whsec_" + base64.StdEncoding.EncodeToString(key)
	s.rx = webhookrx.New(s.secret)
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "0.0.0.0:0") //nolint:gosec // G102: ffs delivers from the cluster through the host's address
	require.NoError(t, err)
	rxSrv := httptest.NewUnstartedServer(s.rx)
	_ = rxSrv.Listener.Close()
	rxSrv.Listener = ln
	rxSrv.Start()
	t.Cleanup(rxSrv.Close)
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	s.rxURL = "http://" + net.JoinHostPort(s.env.HostAddr, port) + "/"
	t.Cleanup(func() { s.dumpOnFailure(t) })

	// The first Grype DB build, a small one from the feed's fixtures, is out before ffs starts, so the feed
	// installs it first thing; grypedb-update publishes the next. Both are stamped in the past, so neither counts
	// towards settling the OSV findings the suite observes (they stay provisional, as without the feed).
	s.grypeFirst = s.feeds.PublishGrypeDB(grypedbtest.BuildDB(t, grypeBuilt.Add(-24*time.Hour), "**/debian-12/cve-2022-38178.json"),
		grypeBuilt.Add(-24*time.Hour))

	s.appRepo = s.env.RegistryPush + "/e2e/app"
	digest := pushAppIndex(t, s.appRepo+":1")
	t.Logf("pushed %s:1 (%s)", s.appRepo, digest)

	repo, tag := s.env.ffsImage(t)
	pullPolicy := "Never" // kind-loaded
	if s.env.FFSImage != "" {
		pullPolicy = "IfNotPresent"
	}
	base := s.feeds.BaseURL(s.env.HostAddr)
	s.values = map[string]any{
		"image":       map[string]any{"repository": repo, "tag": tag, "pullPolicy": pullPolicy},
		"persistence": map[string]any{"size": "2Gi"},
		// 1800 MiB, below the 2Gi emptyDir limit.
		"catalog": map[string]any{"scratchSizeLimit": "2Gi", "scratchLimit": 1887436800},
		// The e2e image is built for the host's architecture, amd64 or arm64, both of which the agent
		// schedules on by default. maxImageBytes keeps the kind-loaded ffs image (well over 16 MiB) out
		// of agent cataloguing, so it stays unresolvable; the side-loaded fixture is a few MiB. The chart
		// wants scratchSizeLimit of at least 1280Mi with that maxImageBytes, and workTimeout plus
		// imageListInterval shorter than staleAfter.
		"nodeAgent": map[string]any{
			"maxImageBytes": "16Mi", "scratchSizeLimit": "2Gi",
			"reportInterval": "10m", "imageListInterval": "20s", "staleAfter": "2m", "runtimeGrace": "2m", "workTimeout": "90s",
		},
		"config": map[string]any{
			"clusterName": "e2e",
			"registry":    map[string]any{"mirrors": map[string]any{s.env.RegistryPush: s.env.RegistryInCluster}},
			"crd":         map[string]any{"minPriority": "medium"},
			"upgrades":    map[string]any{"enabled": false},
			"feeds": map[string]any{
				"grypedb": map[string]any{"url": base + grypeListingPath, "interval": "10s"},
				"epss":    map[string]any{"enabled": false},
				"eol":     map[string]any{"enabled": false},
				"osv":     map[string]any{"url": base + "/osv", "interval": "10s"},
				"cvelist": map[string]any{"url": base + "/cvelist/download", "interval": "10s"},
				"kev":     map[string]any{"url": base + kevPath, "interval": "10s"},
			},
		},
	}
	values, err := yaml.Marshal(s.values)
	require.NoError(t, err)
	if !k3sMode() {
		appendHostPackage(t)
	}
	out := helmInstall(t, values)
	require.Contains(t, out, "kubectl -n ffs port-forward deploy/ffs 8080")
	return s
}

// dumpOnFailure logs what explains a failure: the ffs and agent logs, the feed requests and the
// deliveries.
func (s *suite) dumpOnFailure(t *testing.T) {
	if !t.Failed() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, c := range []string{"controller", "catalog"} {
		out, err := exec.CommandContext(ctx, "kubectl", "-n", "ffs", "logs", "deploy/ffs", "-c", c, "--tail=200").CombinedOutput() //nolint:gosec // G204: c is one of two fixed container names
		t.Logf("ffs %s logs (err %v):\n%s", c, err, out)
	}
	for _, c := range []string{"collector", "catalog"} {
		out, err := exec.CommandContext(ctx, "kubectl", "-n", agentNS, "logs", "ds/"+agentDS, "-c", c, "--tail=200").CombinedOutput() //nolint:gosec // G204: c is one of two fixed container names
		t.Logf("agent %s logs (err %v):\n%s", c, err, out)
	}
	t.Logf("feed server requests (last 300):\n%s", s.feeds.RequestLog(300))
	for _, d := range s.rx.Deliveries() {
		t.Logf("delivery %s type=%s verified=%t received=%s readError=%q", d.ID, d.Type, d.Verified,
			d.Received.UTC().Format(time.RFC3339), d.ReadErr)
	}
}

// waitDelivery waits up to timeout for a delivery that matches and is verified.
func (s *suite) waitDelivery(t *testing.T, timeout time.Duration, what string, match func(webhookrx.Delivery) bool) webhookrx.Delivery {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()
	d, err := s.rx.Wait(ctx, match)
	require.NoError(t, err, "no delivery of %s within %s", what, timeout)
	require.True(t, d.Verified, "delivery %s (%s) did not verify", d.ID, d.Type)
	return d
}

// mentions reports whether a delivery's body names advisory id.
func mentions(d webhookrx.Delivery, id string) bool { return bytes.Contains(d.Body, []byte(id)) }

// waitPriority waits until the Finding exists with one of want as its priority.
func waitPriority(t *testing.T, timeout time.Duration, ns, name string, want ...string) {
	t.Helper()
	eventually(t, timeout, func() (bool, string) {
		p, ok, err := findingPriority(t.Context(), ns, name)
		switch {
		case err != nil:
			return false, err.Error()
		case !ok:
			return false, fmt.Sprintf("finding %s/%s does not exist", ns, name)
		}
		return slices.Contains(want, p), fmt.Sprintf("finding %s/%s priority %q, want %v", ns, name, p, want)
	})
}

// waitGone waits until the Finding no longer exists.
func waitGone(t *testing.T, timeout time.Duration, ns, name string) {
	t.Helper()
	eventually(t, timeout, func() (bool, string) {
		p, ok, err := findingPriority(t.Context(), ns, name)
		if err != nil {
			return false, err.Error()
		}
		return !ok, fmt.Sprintf("finding %s/%s still exists at priority %q", ns, name, p)
	})
}

// waitEvent waits for an Event about the app Deployment with reason, and returns it.
func waitEvent(t *testing.T, reason string) eventsv1.Event {
	t.Helper()
	var got eventsv1.Event
	eventually(t, time.Minute, func() (bool, string) {
		evs, err := ownerEvents(t.Context(), "e2e", "Deployment", "app")
		if err != nil {
			return false, err.Error()
		}
		var reasons []string
		for _, e := range evs {
			if e.Reason == reason {
				got = e
				return true, ""
			}
			reasons = append(reasons, e.Reason)
		}
		return false, fmt.Sprintf("no %s Event on deploy/app; reasons %v", reason, reasons)
	})
	return got
}

func expires() string { return time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339) }

func (s *suite) baseline(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "e2e-webhook", Namespace: "ffs"},
		StringData: map[string]string{"url": s.rxURL, "signingSecret": s.secret},
	}
	_, err := kube.CoreV1().Secrets("ffs").Create(t.Context(), secret, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		_, err = kube.CoreV1().Secrets("ffs").Update(t.Context(), secret, metav1.UpdateOptions{})
	}
	require.NoError(t, err)
	apply(t, "alerttarget.yaml", nil)
	s.waitDelivery(t, 3*time.Minute, "the baseline", func(webhookrx.Delivery) bool { return true })
}

func (s *suite) catalogued(t *testing.T) {
	apply(t, "app.yaml", map[string]string{"APP_IMAGE": s.appRepo + ":1"})
	run(t, "kubectl", "-n", "e2e", "rollout", "status", "deploy/app", "--timeout", "3m")
	nodes, err := kube.CoreV1().Nodes().List(t.Context(), metav1.ListOptions{})
	require.NoError(t, err)
	require.NotEmpty(t, nodes.Items)
	platform := "linux/" + nodes.Items[0].Status.NodeInfo.Architecture

	base := portForward(t)
	eventually(t, 5*time.Minute, func() (bool, string) {
		objs, err := apiObjects(t.Context(), base, "/api/v1/images?limit=200")
		if err != nil {
			return false, err.Error() // a port-forward hiccup or a restart: poll again
		}
		// A repository can appear more than once (an entry per digest, and nested objects), so one matching
		// entry is enough, wherever it is.
		var app, self []string
		appOK, selfUnresolvable := false, false
		for _, o := range objs {
			switch o["repo"] {
			case s.appRepo:
				appOK = appOK || (o["status"] == "catalogued" && o["platform"] == platform)
				app = append(app, fmt.Sprintf("status %v platform %v", o["status"], o["platform"]))
			case "ghcr.io/the-it-dept/ffs":
				selfUnresolvable = selfUnresolvable || o["status"] == "unresolvable"
				self = append(self, fmt.Sprint(o["status"]))
			}
		}
		if !appOK {
			return false, fmt.Sprintf("image %s %v, want catalogued on %s", s.appRepo, app, platform)
		}
		// The kind-loaded ffs image has only a node-local config digest. A registry-pulled one
		// (k3s) resolves normally.
		if s.env.FFSImage == "" && !selfUnresolvable {
			return false, fmt.Sprintf("image ghcr.io/the-it-dept/ffs status %v, want unresolvable", self)
		}
		return true, ""
	})
}

// grypeBuilt stamps the second fixture Grype DB build, a day before the suite runs; the first is a day older.
var grypeBuilt = time.Now().UTC().Truncate(time.Second).Add(-24 * time.Hour)

// feedStatus is one entry of GET /api/v1/feeds.
type feedStatus struct {
	Name        string    `json:"name"`
	LastSuccess time.Time `json:"lastSuccess"`
	LastAttempt time.Time `json:"lastAttempt"`
	LastError   string    `json:"lastError"`
}

// grypeFeed returns the grypedb entry of GET /api/v1/feeds.
func grypeFeed(ctx context.Context, base string) (feedStatus, error) {
	var body bytes.Buffer
	code, err := get(ctx, base+"/api/v1/feeds", &body)
	if err != nil {
		return feedStatus{}, err
	}
	if code != http.StatusOK {
		return feedStatus{}, fmt.Errorf("GET /api/v1/feeds: %d %s", code, body.String())
	}
	var page struct {
		Feeds []feedStatus `json:"feeds"`
	}
	if err := json.Unmarshal(body.Bytes(), &page); err != nil {
		return feedStatus{}, fmt.Errorf("GET /api/v1/feeds: %w", err)
	}
	for _, f := range page.Feeds {
		if f.Name == "grypedb" {
			return f, nil
		}
	}
	return feedStatus{}, fmt.Errorf("GET /api/v1/feeds: no grypedb feed in %s", body.String())
}

// grypeDBUpdate covers the Grype DB feed in the cluster (F120): the first build, published before the install, is
// installed and hydrated, and the matcher loads it; a second build is then downloaded, installed, hydrated and diffed
// against the first while the matcher holds the first open, and handed to the engine. The feed's lastSuccess
// advancing past the second download, with no error, says all of that worked.
func (s *suite) grypeDBUpdate(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	require.NoError(t, s.feeds.WaitServed(ctx, s.grypeFirst, time.Time{}), "the first Grype DB build was never downloaded")
	base := portForward(t)
	eventually(t, 3*time.Minute, func() (bool, string) {
		f, err := grypeFeed(t.Context(), base)
		if err != nil {
			return false, err.Error()
		}
		return !f.LastSuccess.IsZero() && f.LastError == "", fmt.Sprintf("grypedb feed %+v, want the first build installed", f)
	})

	published := time.Now()
	second := s.feeds.PublishGrypeDB(grypedbtest.BuildDB(t, grypeBuilt), grypeBuilt)
	require.NoError(t, s.feeds.WaitServed(ctx, second, published), "the second Grype DB build was never downloaded")
	downloaded := time.Now()
	// The success of the sync that took the second build is recorded when the sync ends, after the download. The
	// sync before it ended a whole interval (10s, less 10% jitter) earlier, so a success up to 2s before the
	// download, allowing for clock skew with the node, can only be this one.
	eventually(t, 4*time.Minute, func() (bool, string) {
		f, err := grypeFeed(t.Context(), base)
		if err != nil {
			return false, err.Error()
		}
		return f.LastSuccess.After(downloaded.Add(-2*time.Second)) && f.LastError == "",
			fmt.Sprintf("grypedb feed %+v, want a success after the second build's download at %s", f, downloaded.UTC().Format(time.RFC3339Nano))
	})
}

var assetRef = regexp.MustCompile(`(?:src|href)="(/assets/[^"]+\.js)"`)

// uiLoads checks the embedded web UI over the port-forward: the SPA shell for / and for a client route,
// then one hashed asset with immutable caching.
func (s *suite) uiLoads(t *testing.T) {
	base := portForward(t)
	code, hdr, body := fetch(t, base+"/")
	require.Equal(t, http.StatusOK, code)
	require.True(t, strings.HasPrefix(hdr.Get("Content-Type"), "text/html"), hdr.Get("Content-Type"))
	require.Equal(t, web.CSP, hdr.Get("Content-Security-Policy"))
	require.Contains(t, string(body), `id="root"`)
	m := assetRef.FindSubmatch(body)
	require.NotNil(t, m, "index.html references no /assets/*.js:\n%s", body)
	code, hdr, _ = fetch(t, base+string(m[1]))
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, "public, max-age=31536000, immutable", hdr.Get("Cache-Control"))
	code, _, body = fetch(t, base+"/vulnerabilities")
	require.Equal(t, http.StatusOK, code)
	require.Contains(t, string(body), `id="root"`)
}

func (s *suite) detected(t *testing.T) {
	// The CNA record (severity) goes out first, as it usually does upstream.
	at := time.Now()
	asset := s.feeds.PublishCVE(cveDebian, cnaRecord(cveDebian, "Example", "example", "", "0", "1.0-2", 9.8, "CRITICAL", at))
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	require.NoError(t, s.feeds.WaitServed(ctx, asset, at))
	at = time.Now()
	s.feeds.PublishOSV("Debian", "DEBIAN-"+cveDebian, debianOSV("DEBIAN-"+cveDebian, cveDebian, "example", "1.0-2", "12", "bookworm", at), at)

	// Critical with a fix, not exposed.
	waitPriority(t, 4*time.Minute, "e2e", findingDebian, "high")
	ev := waitEvent(t, "VulnerabilitiesDetected")
	require.Equal(t, corev1.EventTypeWarning, ev.Type)
	require.LessOrEqual(t, len(ev.Note), 1024)
	// The digest puts the finding in the ledger, so its next alert is an escalation.
	s.waitDelivery(t, 2*time.Minute, "a digest naming "+cveDebian, func(d webhookrx.Delivery) bool {
		return d.Type == typeDigest && mentions(d, cveDebian)
	})
}

func (s *suite) exposed(t *testing.T) {
	at := time.Now()
	apply(t, "service-nodeport.yaml", nil)
	waitPriority(t, 2*time.Minute, "e2e", findingDebian, "urgent") // critical and exposed
	waitEvent(t, "VulnerabilitiesEscalated")
	s.waitDelivery(t, 2*time.Minute, "an escalation of "+cveDebian, func(d webhookrx.Delivery) bool {
		return d.Type == typeEscalated && mentions(d, cveDebian) && d.Received.After(at)
	})
}

func (s *suite) kevImmediate(t *testing.T) {
	// KEV lists the CVE before its CNA record (the record that matches) is out.
	at := time.Now()
	s.feeds.PublishKEV(cvePHP, at)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	require.NoError(t, s.feeds.WaitServed(ctx, kevPath, at))
	published := time.Now()
	s.feeds.PublishCVE(cvePHP, cnaRecord(cvePHP, "PHP Group", "PHP", "https://github.com/php/php-src", "8.3.*", "8.3.12", 7.5, "HIGH", published))

	waitPriority(t, 3*time.Minute, "e2e", findingPHP, "urgent")
	// The every-minute digest may have recorded the finding at a lower priority before the KEV
	// enrichment landed, so either alert type is right.
	s.waitDelivery(t, time.Until(published.Add(2*time.Minute)), "an immediate alert for "+cvePHP, func(d webhookrx.Delivery) bool {
		return (d.Type == typeDetected || d.Type == typeEscalated) && mentions(d, cvePHP) &&
			d.Received.After(published) && d.Received.Before(published.Add(2*time.Minute))
	})
}

func (s *suite) tenantCannotExceptUrgent(t *testing.T) {
	apply(t, "exception-tenant.yaml", map[string]string{"EXPIRES": expires()})
	time.Sleep(75 * time.Second)
	_, ok, err := findingPriority(t.Context(), "e2e", findingPHP)
	require.NoError(t, err)
	require.True(t, ok, "a tenant Exception removed urgent finding %s", findingPHP)

	var ex v1alpha1.Exception
	raw, err := kube.CoreV1().RESTClient().Get().AbsPath("/apis/ffs.theitdept.au/v1alpha1/namespaces/e2e/exceptions/e2e-tenant").DoRaw(t.Context())
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &ex))
	require.EqualValues(t, 1, ex.Status.UrgentNotExcepted)
	c := apimeta.FindStatusCondition(ex.Status.Conditions, "UrgentNotExcepted")
	require.NotNil(t, c, "conditions %+v", ex.Status.Conditions)
	require.Equal(t, metav1.ConditionTrue, c.Status)
	require.Equal(t, "UrgentRequiresAdmin", c.Reason)
	require.Contains(t, c.Message, "urgent")
}

func (s *suite) adminExceptionSilences(t *testing.T) {
	apply(t, "exception-admin.yaml", map[string]string{"EXPIRES": expires()})
	s.t7 = time.Now()
	waitGone(t, 2*time.Minute, "e2e", findingPHP)
}

func (s *suite) notRunning(t *testing.T) {
	run(t, "kubectl", "-n", "e2e", "scale", "deploy/app", "--replicas=0")
	waitPriority(t, 2*time.Minute, "e2e", findingDebian, "high", "medium")
}

func (s *suite) resolved(t *testing.T) {
	run(t, "kubectl", "-n", "e2e", "delete", "deploy/app")
	s.t9 = time.Now()
	waitGone(t, 2*time.Minute, "e2e", findingDebian)
	// It was alerted immediately (exposed), so its resolution goes out immediately too.
	s.waitDelivery(t, 2*time.Minute, "the resolution of "+cveDebian, func(d webhookrx.Delivery) bool {
		return d.Type == typeResolved && mentions(d, cveDebian) && d.Received.After(s.t9)
	})
}

func (s *suite) hygiene(t *testing.T) {
	for _, d := range s.rx.Deliveries() {
		require.True(t, d.Verified, "delivery %s (%s) did not verify", d.ID, d.Type)
		if strings.HasPrefix(d.Type, eventPrefix+"finding.") && d.Received.After(s.t7) {
			require.False(t, mentions(d, cvePHP), "delivery %s (%s) names %s after the admin Exception", d.ID, d.Type, cvePHP)
		}
	}

	pods, err := kube.CoreV1().Pods("ffs").List(t.Context(), metav1.ListOptions{LabelSelector: "app.kubernetes.io/name=ffs"})
	require.NoError(t, err)
	require.NotEmpty(t, pods.Items)
	for _, p := range pods.Items {
		for _, c := range p.Status.ContainerStatuses {
			require.Zero(t, c.RestartCount, "pod %s container %s restarted", p.Name, c.Name)
		}
	}

	evs, err := ownerEvents(t.Context(), "ffs", "Deployment", "ffs")
	require.NoError(t, err)
	for _, e := range evs {
		require.NotEqual(t, "FeedStale", e.Reason, "FeedStale Event: %s", e.Note)
	}
}
