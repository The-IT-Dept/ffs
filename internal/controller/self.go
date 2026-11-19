package controller

import (
	"context"
	"fmt"
	"net"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// dialTimeout bounds each cataloguer socket probe.
const dialTimeout = time.Second

// FindSelf returns a reference to the ffs Deployment namespace/deploymentName, read through r. It
// returns an error when the Deployment cannot be read, including when it does not exist.
func FindSelf(ctx context.Context, r client.Reader, namespace, deploymentName string) (*corev1.ObjectReference, error) {
	var dep appsv1.Deployment
	if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: deploymentName}, &dep); err != nil {
		return nil, fmt.Errorf("get Deployment %s/%s: %w", namespace, deploymentName, err)
	}
	return &corev1.ObjectReference{
		APIVersion: appsv1.SchemeGroupVersion.String(), Kind: "Deployment",
		Namespace: dep.Namespace, Name: dep.Name, UID: dep.UID,
	}, nil
}

// dialSocket connects to the unix socket at path, with dialTimeout, and closes the connection.
func dialSocket(ctx context.Context, path string) error {
	d := net.Dialer{Timeout: dialTimeout}
	c, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return err
	}
	return c.Close()
}

// waitForSocket dials the unix socket at path now and then every interval until a dial succeeds,
// which returns true, or ctx is done, which returns false.
func waitForSocket(ctx context.Context, path string, every time.Duration) bool {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if dialSocket(ctx, path) == nil {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
		}
	}
}
