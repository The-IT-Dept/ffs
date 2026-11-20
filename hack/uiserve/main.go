// Command uiserve serves the ffs web UI and read-only API over a seeded store, for UI development
// and the browser tests. It is not part of the image.
//
//	go run ./hack/uiserve [--fixture small|scale] [--addr 127.0.0.1:8099] [--control 127.0.0.1:8098]
//
// The store is the webtest Small fixture (or the 25,000-finding Scale fixture) in a temporary
// directory, behind the same handler, guards and live-update hub as ffs itself. `npm run dev` in
// ui/ proxies /api to it on 8099, and the Playwright suite runs against it. The control listener
// answers POST /transition by adding one urgent finding to Deployment/shop/web and announcing the
// change on the event stream, so a test can watch an open page update.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/go-logr/logr"

	"github.com/the-it-dept/ffs/internal/web"
	"github.com/the-it-dept/ffs/internal/web/apiserver"
	"github.com/the-it-dept/ffs/internal/web/live"
	"github.com/the-it-dept/ffs/internal/web/ui"
	"github.com/the-it-dept/ffs/internal/web/webtest"
)

// options are the command's flags.
type options struct{ Addr, Control, Fixture string }

func main() {
	var o options
	flag.StringVar(&o.Addr, "addr", "127.0.0.1:8099", "address of the web UI and API")
	flag.StringVar(&o.Control, "control", "127.0.0.1:8098", "address of the control listener (POST /transition)")
	flag.StringVar(&o.Fixture, "fixture", "small", "seeded store: small or scale")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, o, logr.FromSlogHandler(slog.NewTextHandler(os.Stderr, nil)))
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "uiserve:", err)
		os.Exit(1)
	}
}

// run serves the fixture until ctx ends, then shuts both listeners down. It returns the first
// server error, or nil after ctx ends.
func run(ctx context.Context, o options, log logr.Logger) (err error) {
	dir, err := os.MkdirTemp("", "ffs-uiserve-")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(dir)) }()
	if o.Fixture == "scale" {
		log.Info("building the scale fixture; this takes a while")
	}
	f, err := openFixture(ctx, o.Fixture, dir)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	hub := newHub(f, log)
	go func() {
		if err := hub.Start(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Error(err, "live hub stopped")
		}
	}()

	cfg := f.Config
	cfg.Listen = o.Addr
	errs := make(chan error, 2)
	srv := web.NewServer(cfg, handlers(f, hub), hub.Close)
	go func() { errs <- srv.Start(ctx) }()

	ctl := &http.Server{Addr: o.Control, Handler: newControl(f.Store, cfg.ClusterName, hub), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := ctl.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			errs <- fmt.Errorf("control listener: %w", err)
		}
	}()
	go func() {
		<-ctx.Done()
		sctx, scancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer scancel()
		_ = ctl.Shutdown(sctx)
	}()

	log.Info("serving", "addr", o.Addr, "control", o.Control, "fixture", o.Fixture)
	select {
	case err := <-errs:
		cancel()
		return err
	case <-ctx.Done():
		// The web server returns once it has shut down.
		return <-errs
	}
}

// openFixture builds the named fixture with its store at dir/ffs.db.
func openFixture(ctx context.Context, kind, dir string) (*webtest.Fixture, error) {
	path := filepath.Join(dir, "ffs.db")
	switch kind {
	case "small":
		return webtest.Small(ctx, path)
	case "scale":
		return webtest.Scale(ctx, path, webtest.DefaultScale)
	}
	return nil, fmt.Errorf("fixture must be small or scale, not %q", kind)
}

// newHub is the live-update hub over f's store, with the production timings. The fixture's node
// data never changes, so the node mark is constant.
func newHub(f *webtest.Fixture, log logr.Logger) *live.Hub {
	return live.NewHub(live.Options{
		Store: f.Store, Marks: f.Store, Nodes: func(context.Context) (string, error) { return "", nil },
		Coalesce: 2 * time.Second, Poll: 2 * time.Second, Heartbeat: 25 * time.Second, Ring: 256, MaxStreams: 64,
		Now: time.Now, Log: log.WithName("live"), Cluster: f.Config.ClusterName,
	})
}

// handlers routes the API over f, the stream to hub and every other path to the embedded UI.
func handlers(f *webtest.Fixture, hub *live.Hub) web.Handlers {
	return web.Handlers{API: apiserver.New(f.Options()).Handler(), Stream: hub, UI: ui.Handler(ui.Dist())}
}
