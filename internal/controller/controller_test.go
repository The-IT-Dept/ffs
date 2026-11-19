package controller

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/the-it-dept/ffs/api/v1alpha1"
	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/store"
)

func TestManagerOptions(t *testing.T) {
	o := managerOptions(Options{Config: config.Default(), LeaderElect: true, MetricsAddr: ":8443", ProbeAddr: ":8081"}, "ffs")

	require.Equal(t, "0", o.PprofBindAddress)
	require.True(t, o.LeaderElection)
	require.Equal(t, "ffs.theitdept.au", o.LeaderElectionID)
	require.Equal(t, "ffs", o.LeaderElectionNamespace)
	require.True(t, o.LeaderElectionReleaseOnCancel)
	require.Equal(t, ":8081", o.HealthProbeBindAddress)
	require.Equal(t, ":8443", o.Metrics.BindAddress)
	require.True(t, o.Metrics.SecureServing)
	require.NotNil(t, o.Metrics.FilterProvider)
	require.NotNil(t, o.GracefulShutdownTimeout)
	require.Equal(t, 30*time.Second, *o.GracefulShutdownTimeout)

	require.NotNil(t, o.Client.Cache)
	require.Contains(t, o.Client.Cache.DisableFor, client.Object(&corev1.Secret{}))

	require.NotNil(t, o.Cache.DefaultTransform)
	transformed := map[string]bool{}
	for obj, by := range o.Cache.ByObject {
		transformed[fmt.Sprintf("%T", obj)] = by.Transform != nil
	}
	for _, obj := range []client.Object{&corev1.Pod{}, &corev1.Node{}, &appsv1.Deployment{}, &appsv1.StatefulSet{},
		&appsv1.DaemonSet{}, &batchv1.Job{}, &batchv1.CronJob{}} {
		require.True(t, transformed[fmt.Sprintf("%T", obj)], "%T has no cache transform", obj)
	}
}

// disableAllFeeds turns every feed off, so Run makes no outbound requests.
func disableAllFeeds(c *config.Config) {
	for _, f := range []*config.FeedConfig{&c.Feeds.GrypeDB, &c.Feeds.OSV, &c.Feeds.CVEList, &c.Feeds.KEV,
		&c.Feeds.EPSS, &c.Feeds.EOL, &c.Feeds.NVD, &c.Feeds.ChainguardOSV} {
		f.Enabled = false
	}
}

func TestController_StartStopFeedsDisabled(t *testing.T) {
	needEnv(t)
	dir, err := os.MkdirTemp("", "ffs") // short path: macOS caps unix socket paths at 104 bytes
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "catalog.sock")
	var lc net.ListenConfig
	l, err := lc.Listen(context.Background(), "unix", sock) // satisfies the catalog gate
	require.NoError(t, err)
	defer func() { _ = l.Close() }()

	c := config.Default()
	c.StorePath, c.DataDir, c.Catalog.Socket = filepath.Join(dir, "ffs.db"), dir, sock
	disableAllFeeds(&c)
	require.NoError(t, c.Validate())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, env.Config, Options{Config: c, LeaderElect: true, MetricsAddr: "0", ProbeAddr: "0", Namespace: "default"})
	}()

	ex := &v1alpha1.Exception{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "accept"},
		Spec: v1alpha1.ExceptionSpec{Reason: "test", Expires: metav1.NewTime(time.Now().Add(24 * time.Hour)),
			Advisories: []string{"CVE-2026-41873"}},
	}
	require.NoError(t, env.Client.Create(context.Background(), ex))
	t.Cleanup(func() { _ = env.Client.Delete(context.Background(), ex) })

	// Ready=True proves leader election, the cache and the leader-only Exception reconciler.
	require.Eventually(t, func() bool {
		var got v1alpha1.Exception
		if err := env.Client.Get(context.Background(), client.ObjectKeyFromObject(ex), &got); err != nil {
			return false
		}
		return apimeta.IsStatusConditionTrue(got.Status.Conditions, "Ready")
	}, 20*time.Second, 100*time.Millisecond)

	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not return within 30s of cancel")
	}

	// The store was closed cleanly and reopens.
	st, err := store.Open(context.Background(), c.StorePath)
	require.NoError(t, err)
	defer func() { require.NoError(t, st.Close()) }()
	rules, err := st.ExceptionRules(context.Background())
	require.NoError(t, err)
	var keys []string
	for _, r := range rules {
		keys = append(keys, r.Key())
	}
	require.Contains(t, keys, "default/accept")
}
