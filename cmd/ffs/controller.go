package main

import (
	"flag"
	"os"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/controller"
)

func newControllerCmd() *cobra.Command {
	var (
		configPath string
		opts       controller.Options
		logOpts    zap.Options
	)
	cmd := &cobra.Command{
		Use:   "controller",
		Short: "Run the in-cluster controller",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			installLogger(zap.New(zap.UseFlagOptions(&logOpts)))
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}
			rc, err := ctrl.GetConfig()
			if err != nil {
				return err
			}
			opts.Config = cfg
			if opts.PprofAddr == "" {
				opts.PprofAddr = os.Getenv(controller.PprofAddrEnv)
			}
			// cmd.Context() is cancelled on SIGTERM and SIGINT (main), so SetupSignalHandler is not used.
			return controller.Run(cmd.Context(), rc, opts)
		},
	}
	f := cmd.Flags()
	f.StringVar(&configPath, "config", "/etc/ffs/config.yaml", "path of the YAML configuration file")
	f.BoolVar(&opts.LeaderElect, "leader-elect", true, "use leader election so only one replica writes")
	f.StringVar(&opts.MetricsAddr, "metrics-bind-address", ":8443", `address the authenticated metrics endpoint listens on; "0" disables it`)
	f.StringVar(&opts.ProbeAddr, "health-probe-bind-address", ":8081", `address the health probes listen on; "0" disables them`)
	f.StringVar(&opts.PprofAddr, "pprof-bind-address", "",
		"loopback address of a diagnostic pprof listener; off when empty (also "+controller.PprofAddrEnv+")")
	_ = f.MarkHidden("pprof-bind-address")
	// --zap-log-level, --zap-encoder, --zap-devel, --zap-stacktrace-level and --zap-time-encoding; for example
	// --zap-log-level=debug (or 1) turns on V(1) messages.
	zfs := flag.NewFlagSet("zap", flag.ContinueOnError)
	logOpts.BindFlags(zfs)
	f.AddGoFlagSet(zfs)
	return cmd
}

// installLogger installs the logger the controller command builds from its --zap-* flags: setLogger, which a test
// replaces to see that logger.
var installLogger = setLogger

// setLogger makes l the logger of controller-runtime and of klog, so client-go and leader election log through it,
// in the same format and at the same level, rather than as klog text among the JSON lines.
func setLogger(l logr.Logger) {
	ctrl.SetLogger(l)
	klog.SetLogger(l)
}
