package main

import (
	"errors"

	"github.com/spf13/cobra"
)

func newControllerCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "controller",
		Short: "Run the in-cluster controller",
		RunE: func(*cobra.Command, []string) error {
			return errors.New("not implemented")
		},
	}
}
