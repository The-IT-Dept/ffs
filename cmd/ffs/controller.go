package main

import (
	"github.com/spf13/cobra"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/controller"
)

func newControllerCmd() *cobra.Command {
	var (
		configPath string
		opts       controller.Options
	)
	cmd := &cobra.Command{
		Use:   "controller",
		Short: "Run the in-cluster controller",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctrl.SetLogger(zap.New())
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}
			rc, err := ctrl.GetConfig()
			if err != nil {
				return err
			}
			opts.Config = cfg
			// cmd.Context() is cancelled on SIGTERM and SIGINT (main), so SetupSignalHandler is not used.
			return controller.Run(cmd.Context(), rc, opts)
		},
	}
	f := cmd.Flags()
	f.StringVar(&configPath, "config", "/etc/ffs/config.yaml", "path of the YAML configuration file")
	f.BoolVar(&opts.LeaderElect, "leader-elect", true, "use leader election so only one replica writes")
	f.StringVar(&opts.MetricsAddr, "metrics-bind-address", ":8443", `address the authenticated metrics endpoint listens on; "0" disables it`)
	f.StringVar(&opts.ProbeAddr, "health-probe-bind-address", ":8081", `address the health probes listen on; "0" disables them`)
	return cmd
}
