package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/go-logr/logr/funcr"
	"github.com/spf13/cobra"

	"github.com/the-it-dept/ffs/internal/agent"
)

func newAgentCmd() *cobra.Command {
	var (
		o              agent.Options
		hostRoot, dist string
		heartbeat      string
		checkMaxAge    time.Duration
	)
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Report this node's host inventory and cached images to the controller",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			d, err := agent.ParseDistribution(dist)
			if err != nil {
				return err
			}
			if o.Controller == "" {
				return errors.New("--controller is required")
			}
			o.HostRoot, o.Distribution = agent.HostRoot(hostRoot), d
			o.Log = funcr.NewJSON(func(obj string) { fmt.Fprintln(os.Stderr, obj) }, funcr.Options{})
			return agent.Run(cmd.Context(), o)
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.Controller, "controller", "", "https URL of the controller's agent API")
	f.StringVar(&o.CAFile, "ca-file", "/etc/ffs-agent/ca/ca.crt", "CA bundle that signs the controller's agent API certificate")
	f.StringVar(&o.TokenFile, "token-file", "/var/run/secrets/ffs-agent/token", "projected service-account token for the agent API")
	f.StringVar(&o.NodeName, "node-name", os.Getenv("NODE_NAME"), "name of this node (default $NODE_NAME)")
	f.StringVar(&hostRoot, "host-root", "/host", "directory the read-only host paths are mounted under")
	f.StringVar(&dist, "distribution", "containerd", "host-path table: containerd, k3s, rke2 or crio")
	f.StringVar(&o.ContentStore, "content-store", "", "containerd content store (container path); empty uses the distribution's path under --host-root")
	f.StringVar(&o.Scratch, "scratch", "/scratch/stage", "directory shared with the cataloguer for staged inputs")
	f.StringVar(&o.CatalogSocket, "catalog-socket", "/run/ffs/catalog.sock", "unix socket of the cataloguer")
	f.Int64Var(&o.MaxImageBytes, "max-image-bytes", 1073741824, "largest image catalogued from the content store")
	f.StringVar(&o.Heartbeat, "heartbeat", "/scratch/heartbeat", "file touched after every report; the liveness probe reads it")
	f.StringArrayVar(&o.ExtraBinDirs, "extra-bin-dir", nil, "extra host directory searched for known binaries (repeatable)")

	check := &cobra.Command{
		Use:    "check",
		Short:  "Exit 1 when the agent's heartbeat is missing or stale",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return agent.CheckHeartbeat(heartbeat, checkMaxAge, time.Now())
		},
	}
	check.Flags().StringVar(&heartbeat, "heartbeat", "/scratch/heartbeat", "heartbeat file the agent touches")
	check.Flags().DurationVar(&checkMaxAge, "max-age", 15*time.Minute, "oldest heartbeat that counts as alive")
	cmd.AddCommand(check)
	return cmd
}
