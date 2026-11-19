package registry

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/registry/regtest"
)

func dockerConfigSecret(t *testing.T, ns, name, host string) *corev1.Secret {
	t.Helper()
	b, err := json.Marshal(map[string]any{"auths": map[string]any{host: map[string]string{"username": "u", "password": "p"}}})
	require.NoError(t, err)
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Type:       corev1.SecretTypeDockerConfigJson,
		Data:       map[string][]byte{corev1.DockerConfigJsonKey: b},
	}
}

func TestKeychain(t *testing.T) {
	s := regtest.Start(t, regtest.WithBasicAuth("u", "p"))
	s.Push(t, "app:1.0", randomImage(t))
	repo := s.Host + "/app"
	kube := fake.NewClientset(
		dockerConfigSecret(t, "apps", "pull", s.Host),
		dockerConfigSecret(t, "apps", "sa-pull", s.Host),
		&corev1.ServiceAccount{
			ObjectMeta:       metav1.ObjectMeta{Namespace: "apps", Name: "web"},
			ImagePullSecrets: []corev1.LocalObjectReference{{Name: "sa-pull"}},
		},
		dockerConfigSecret(t, "ffs", "regcreds", s.Host),
	)
	clk := newClock()
	newClient := func(cfg config.RegistryConfig) *Client {
		return New(Options{Kube: kube, Namespace: "ffs", Config: cfg, Now: clk.Now})
	}
	resolve := func(c *Client, cs CredSet) error {
		_, err := c.ResolveTag(ctx, repo, "1.0", cs)
		return err
	}

	c := newClient(config.RegistryConfig{ReadPullSecrets: true})
	require.NoError(t, resolve(c, CredSet{Namespace: "apps", ServiceAccount: "web", PullSecrets: []string{"pull"}}))
	require.NoError(t, resolve(c, CredSet{Namespace: "apps", PullSecrets: []string{"pull"}}), "pod secret alone")
	require.NoError(t, resolve(c, CredSet{Namespace: "apps", ServiceAccount: "web"}), "ServiceAccount secret")
	require.ErrorIs(t, resolve(c, CredSet{Namespace: "other"}), ErrUnauthorized)

	// The keychain is reused for five minutes, then read again.
	reads := len(kube.Actions())
	require.NoError(t, resolve(c, CredSet{Namespace: "apps", ServiceAccount: "web"}))
	require.Len(t, kube.Actions(), reads)
	clk.Advance(5 * time.Minute)
	require.NoError(t, resolve(c, CredSet{Namespace: "apps", ServiceAccount: "web"}))
	require.Greater(t, len(kube.Actions()), reads)

	withOperator := newClient(config.RegistryConfig{ReadPullSecrets: true, OperatorSecret: "regcreds"})
	require.NoError(t, resolve(withOperator, CredSet{Namespace: "other"}))

	noPullSecrets := newClient(config.RegistryConfig{ReadPullSecrets: false})
	require.ErrorIs(t, resolve(noPullSecrets, CredSet{Namespace: "apps", ServiceAccount: "web", PullSecrets: []string{"pull"}}), ErrUnauthorized)

	auth, err := c.Auth(ctx, repo, CredSet{Namespace: "apps", ServiceAccount: "web"})
	require.NoError(t, err)
	require.Equal(t, authn.AuthConfig{Username: "u", Password: "p"}, auth)

	for _, a := range kube.Actions() {
		require.Equal(t, "get", a.GetVerb(), "%s %s", a.GetVerb(), a.GetResource().Resource)
		require.Contains(t, []string{"secrets", "serviceaccounts"}, a.GetResource().Resource)
	}
}
