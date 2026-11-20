// Command webhook-receiver receives ffs webhook alerts and logs one JSON line per delivery with
// whether its Standard Webhooks signature verified. The signing secret comes from the
// FFS_WEBHOOK_SECRET environment variable.
//
//	FFS_WEBHOOK_SECRET=whsec_... go run ./hack/webhook-receiver -listen 0.0.0.0:9099
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/the-it-dept/ffs/test/e2e/webhookrx"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "webhook-receiver:", err)
		os.Exit(1)
	}
}

func run() error {
	listen := flag.String("listen", "127.0.0.1:9099", "address to listen on")
	flag.Parse()
	secret := os.Getenv("FFS_WEBHOOK_SECRET")
	if secret == "" {
		return errors.New("FFS_WEBHOOK_SECRET is not set")
	}

	rx := webhookrx.New(secret)
	var mu sync.Mutex
	enc := json.NewEncoder(os.Stdout)
	rx.OnDelivery = func(d webhookrx.Delivery) {
		mu.Lock()
		defer mu.Unlock()
		_ = enc.Encode(struct {
			Received time.Time `json:"received"`
			ID       string    `json:"id"`
			Type     string    `json:"type"`
			Verified bool      `json:"verified"`
			ReadErr  string    `json:"readError,omitempty"`
		}{d.Received.UTC(), d.ID, d.Type, d.Verified, d.ReadErr})
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	srv := &http.Server{Addr: *listen, Handler: rx, ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shutdown)
}
