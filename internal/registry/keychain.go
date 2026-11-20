package registry

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/go-containerregistry/pkg/authn"
	kauth "github.com/google/go-containerregistry/pkg/authn/kubernetes"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// keychainTTL is how long a resolved keychain is reused for one CredSet.
const keychainTTL = 5 * time.Minute

type cachedKeychain struct {
	kc authn.Keychain
	at time.Time
}

// keychain resolves cs to the pod's pull secrets, its ServiceAccount's pull secrets and the operator
// secret, in that order. With none of them it resolves to anonymous. A CredSet without a namespace
// has no pod secrets (kauth would otherwise read the "default" namespace). Secrets are read with Get
// only, and their contents stay in memory: errors never carry secret data.
func (c *Client) keychain(ctx context.Context, cs CredSet) (authn.Keychain, error) {
	key, now := cs.Key(), c.now()
	c.mu.Lock()
	if e, ok := c.keychains[key]; ok && now.Sub(e.at) < keychainTTL {
		c.mu.Unlock()
		return e.kc, nil
	}
	c.mu.Unlock()

	var kcs []authn.Keychain
	if c.kube != nil && c.cfg.ReadPullSecrets && cs.Namespace != "" {
		sa := cs.ServiceAccount
		if sa == "" {
			sa = "default"
		}
		kc, err := kauth.New(ctx, c.kube, kauth.Options{Namespace: cs.Namespace, ServiceAccountName: sa, ImagePullSecrets: cs.PullSecrets})
		if err != nil {
			return nil, secretError(fmt.Sprintf("reading pull secrets in namespace %s", cs.Namespace), err)
		}
		kcs = append(kcs, kc)
	}
	if c.kube != nil && c.cfg.OperatorSecret != "" {
		kc, err := c.operatorKeychain(ctx)
		if err != nil {
			return nil, err
		}
		if kc != nil {
			kcs = append(kcs, kc)
		}
	}
	kc := authn.NewMultiKeychain(kcs...)

	c.mu.Lock()
	for k, e := range c.keychains {
		if now.Sub(e.at) >= keychainTTL {
			delete(c.keychains, k)
		}
	}
	c.keychains[key] = cachedKeychain{kc: kc, at: now}
	c.mu.Unlock()
	return kc, nil
}

// operatorKeychain reads the operator-level dockerconfigjson secret. A configured but missing secret
// contributes nothing, the same as a missing pod pull secret, and is logged when it is first found
// missing (again after it has been seen to exist).
func (c *Client) operatorKeychain(ctx context.Context) (authn.Keychain, error) {
	what := fmt.Sprintf("reading operator secret %s/%s", c.namespace, c.cfg.OperatorSecret)
	s, err := c.kube.CoreV1().Secrets(c.namespace).Get(ctx, c.cfg.OperatorSecret, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		c.operatorSecretSeen(ctx, false)
		return nil, nil
	}
	if err != nil {
		return nil, secretError(what, err)
	}
	c.operatorSecretSeen(ctx, true)
	kc, err := kauth.NewFromPullSecrets(ctx, []corev1.Secret{*s})
	if err != nil {
		return nil, secretError(what, err)
	}
	return kc, nil
}

// operatorSecretSeen records whether the configured operator secret exists, and logs the change to
// missing. Only the reference configured in registry.operatorSecret is logged, never anything read
// from a secret.
func (c *Client) operatorSecretSeen(ctx context.Context, exists bool) {
	c.mu.Lock()
	logIt := !exists && !c.operatorMissing
	c.operatorMissing = !exists
	c.mu.Unlock()
	if logIt {
		logr.FromContextOrDiscard(ctx).WithName("registry").Info("the configured operator registry secret does not exist; "+
			"registries are accessed without it", "secret", c.namespace+"/"+c.cfg.OperatorSecret)
	}
}

// secretError keeps Kubernetes API and network errors (forbidden, timeouts) for diagnosis. Anything
// else comes from parsing secret data and is replaced, because its text can quote the secret.
func secretError(what string, err error) error {
	var status apierrors.APIStatus
	var uerr *url.Error
	if errors.As(err, &status) || errors.As(err, &uerr) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%s: %w", what, err)
	}
	return fmt.Errorf("%s: a pull secret is not valid docker config JSON", what)
}
