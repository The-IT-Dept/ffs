// Command ffs is the ffs vulnerability-intelligence operator.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/the-it-dept/ffs/internal/version"
)

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "ffs",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newVersionCmd(), newControllerCmd(), newCatalogCmd())
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), version.String())
			return err
		},
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := newRootCmd().ExecuteContext(ctx)
	stop()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ffs: %v\n", err)
		os.Exit(1)
	}
}
