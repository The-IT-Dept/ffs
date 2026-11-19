package main

import (
	"fmt"
	"os"

	"github.com/go-logr/logr/funcr"
	"github.com/spf13/cobra"

	"github.com/the-it-dept/ffs/internal/catalog"
)

func newCatalogCmd() *cobra.Command {
	var (
		socket, scratch string
		scratchLimit    int64
		maxConcurrent   int
	)
	cmd := &cobra.Command{
		Use:   "catalog",
		Short: "Build the software catalog",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			self, err := os.Executable()
			if err != nil {
				return err
			}
			srv := &catalog.Server{
				ScratchDir:    scratch,
				ScratchLimit:  scratchLimit,
				MaxConcurrent: maxConcurrent,
				Run:           catalog.ExecRunner(self),
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
