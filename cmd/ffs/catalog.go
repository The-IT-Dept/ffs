package main

import (
	"errors"

	"github.com/spf13/cobra"
)

func newCatalogCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "catalog",
		Short: "Build the software catalog",
		RunE: func(*cobra.Command, []string) error {
			return errors.New("not implemented")
		},
	}
}
