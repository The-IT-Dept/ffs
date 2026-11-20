package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/go-logr/logr/funcr"
	"github.com/spf13/cobra"

	"github.com/the-it-dept/ffs/internal/catalog"
)

func newCatalogCmd() *cobra.Command {
	var (
		socket, scratch, localRoot string
		scratchLimit, workerMemory int64
		maxConcurrent, nice        int
	)
	cmd := &cobra.Command{
		Use:   "catalog",
		Short: "Build the software catalog",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if nice < 0 || nice > 19 {
				return errors.New("--nice must be between 0 and 19")
			}
			if workerMemory < 0 {
				return errors.New("--worker-memory-limit must not be negative")
			}
			self, err := os.Executable()
			if err != nil {
				return err
			}
			srv := &catalog.Server{
				ScratchDir:    scratch,
				ScratchLimit:  scratchLimit,
				MaxConcurrent: maxConcurrent,
				LocalRoot:     localRoot,
				Run:           catalog.ExecRunner(self, catalog.WithNice(nice), catalog.WithMemoryLimit(workerMemory)),
				Log:           funcr.NewJSON(func(obj string) { fmt.Fprintln(os.Stderr, obj) }, funcr.Options{}),
			}
			return srv.ListenAndServe(cmd.Context(), socket)
		},
	}
	f := cmd.Flags()
	f.StringVar(&socket, "socket", "/run/ffs/catalog.sock", "unix socket to serve catalog jobs on")
	f.StringVar(&scratch, "scratch", "/scratch", "directory for per-job scratch space")
	f.Int64Var(&scratchLimit, "scratch-limit", 19327352832, "bytes of scratch space all jobs may use together")
	f.IntVar(&maxConcurrent, "max-concurrent", 2, "jobs run at once; further requests are refused as busy")
	f.StringVar(&localRoot, "local-root", "", "local sources (oci-dir, host-dir) must resolve inside this directory; empty refuses them")
	f.IntVar(&nice, "nice", 0, "nice value of catalog workers, 0 to 19")
	f.Int64Var(&workerMemory, "worker-memory-limit", 0, "GOMEMLIMIT of each catalog worker in bytes; 0 keeps the server's")

	cmd.AddCommand(&cobra.Command{
		Use:    "worker",
		Short:  "Catalogue one image read from stdin",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return catalog.RunWorker(cmd.Context(), os.Stdin, os.Stdout)
		},
	})
	return cmd
}
