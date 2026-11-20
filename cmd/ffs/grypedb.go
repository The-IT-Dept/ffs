package main

import (
	"github.com/spf13/cobra"

	"github.com/the-it-dept/ffs/internal/feeds/grypedb"
)

// newGrypeDBDiffCmd is the hidden subcommand the controller re-executes to diff two Grype DB builds
// out of its own process (grypedb.ExecDiffer).
func newGrypeDBDiffCmd() *cobra.Command {
	var oldDir, newDir, out string
	cmd := &cobra.Command{
		Use:    grypedb.DiffCommand,
		Short:  "Diff two Grype database builds and write the changed package keys",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return grypedb.RunDiff(cmd.Context(), oldDir, newDir, out)
		},
	}
	f := cmd.Flags()
	f.StringVar(&oldDir, "old", "", "directory of the current build (a copy the diff may write to)")
	f.StringVar(&newDir, "new", "", "directory of the new build")
	f.StringVar(&out, "out", "", "file to write the changed package keys to, as JSON")
	for _, name := range []string{"old", "new", "out"} {
		_ = cmd.MarkFlagRequired(name) // errors only for a flag that is not defined
	}
	return cmd
}
