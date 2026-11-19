package upgrade

import (
	"fmt"
	"net/http"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/the-it-dept/ffs/internal/controller/deps"
	"github.com/the-it-dept/ffs/internal/engine"
	"github.com/the-it-dept/ffs/internal/registry"
	"github.com/the-it-dept/ffs/internal/sbom"
	"github.com/the-it-dept/ffs/internal/version"
)

var (
	_ Registry        = (*registry.Client)(nil)
	_ Acquirer        = (*sbom.Acquirer)(nil)
	_ Scorer          = (*engine.Engine)(nil)
	_ engine.Observer = (*Resolver)(nil)
)

// httpTimeout bounds each outbound request the resolver makes beyond the registry.
const httpTimeout = 15 * time.Second

// Register adds the leader-only upgrade resolver to m and subscribes it to the engine's match and
// findings changes. It does nothing when upgrades are disabled.
func Register(m manager.Manager, d deps.Deps) error {
	if !d.Config.Upgrades.Enabled {
		return nil
	}
	p, err := NewParser(d.Config.Upgrades.Overrides)
	if err != nil {
		return fmt.Errorf("upgrade: tag overrides: %w", err)
	}
	r := NewResolver(Options{
		Store: d.Store, Registry: d.Registry, Acquirer: d.Acquirer, Scorer: d.Engine, EOL: d.EOL, Parser: p, Config: d.Config,
		HTTP: &http.Client{Timeout: httpTimeout, Transport: uaTransport{base: &http.Transport{Proxy: http.ProxyFromEnvironment}}},
		Log:  d.Log.WithName("upgrade"),
	})
	d.Engine.AddObserver(r)
	return m.Add(manager.RunnableFunc(r.Run))
}

// uaTransport sends every request with the ffs User-Agent, as every other ffs client does.
type uaTransport struct{ base http.RoundTripper }

func (t uaTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	out := req.Clone(req.Context())
	out.Header.Set("User-Agent", version.UserAgent())
	return t.base.RoundTrip(out)
}
