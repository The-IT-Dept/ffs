package controller

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"time"

	"github.com/go-logr/logr"
)

// PprofAddrEnv names the environment variable that turns on the diagnostic pprof listener when the
// controller's hidden --pprof-bind-address flag is not given. It is off by default (spec §7: no
// debug endpoints), and only a loopback address is accepted, so profiles are taken through a port
// forward or from inside the pod.
const PprofAddrEnv = "FFS_PPROF_ADDR"

// checkPprofAddr accepts host:port with an explicit port and a loopback IP literal host. Names,
// "localhost" included, are refused: they resolve through the resolver and /etc/hosts.
func checkPprofAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("pprof address %q: %w", addr, err)
	}
	if port == "" {
		return fmt.Errorf("pprof address %q: needs an explicit port", addr)
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("pprof address %q: only a loopback address is allowed", addr)
}

// pprofMux serves the net/http/pprof handlers on their usual paths, on a mux of its own so nothing
// else registered on http.DefaultServeMux is exposed with them.
func pprofMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return mux
}

// startPprof serves pprof on addr, which must pass checkPprofAddr, until ctx is done or the
// returned stop is called. The listener is bound before it returns, so a bad or busy address is an
// error of the caller's.
func startPprof(ctx context.Context, addr string, log logr.Logger) (stop func(), err error) {
	_, stop, err = startPprofAddr(ctx, addr, log)
	return stop, err
}

// startPprofAddr is startPprof that also returns the address bound, which differs from addr for port 0.
func startPprofAddr(ctx context.Context, addr string, log logr.Logger) (bound string, stop func(), err error) {
	if err := checkPprofAddr(addr); err != nil {
		return "", nil, err
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		return "", nil, fmt.Errorf("pprof listener: %w", err)
	}
	if ta, ok := ln.Addr().(*net.TCPAddr); !ok || !ta.IP.IsLoopback() {
		_ = ln.Close()
		return "", nil, fmt.Errorf("pprof listener bound %s: not a loopback address", ln.Addr())
	}
	srv := &http.Server{Handler: pprofMux(), ReadHeaderTimeout: 10 * time.Second}
	log.Info("diagnostic pprof listener started", "address", ln.Addr().String())
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error(err, "diagnostic pprof listener stopped")
		}
	}()
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
		case <-done:
		}
		_ = srv.Close()
	}()
	return ln.Addr().String(), func() { close(done) }, nil
}
