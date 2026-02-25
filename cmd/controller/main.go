package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/fedor/traforetto/internal/cmdutil"
	"github.com/fedor/traforetto/internal/controller"
)

const (
	envControllerListenAddr  = "TRAFORETTO_CONTROLLER_LISTEN_ADDR"
	envControllerWorkerID    = "TRAFORETTO_CONTROLLER_WORKER_ID"
	envControllerWorkerHost  = "TRAFORETTO_CONTROLLER_WORKER_HOSTNAME"
	envControllerWorkerBase  = "TRAFORETTO_CONTROLLER_WORKER_BASE_URL"
	defaultControllerAddress = ":8080"
	defaultWorkerID          = "worker-local"
	defaultWorkerHost        = "localhost"
	defaultWorkerBaseURL     = "http://localhost:8081"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "controller: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("controller", flag.ContinueOnError)

	listenAddr := fs.String("listen", cmdutil.EnvOrDefault(envControllerListenAddr, defaultControllerAddress), "controller listen address")
	workerID := fs.String("worker-id", cmdutil.EnvOrDefault(envControllerWorkerID, defaultWorkerID), "registered worker ID")
	workerHost := fs.String("worker-hostname", cmdutil.EnvOrDefault(envControllerWorkerHost, defaultWorkerHost), "registered worker hostname")
	workerBaseURL := fs.String("worker-base-url", cmdutil.EnvOrDefault(envControllerWorkerBase, defaultWorkerBaseURL), "registered worker base URL")
	authCfg := cmdutil.BindAuthFlags(fs)

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional args: %v", fs.Args())
	}

	logger := cmdutil.NewLogger("controller")
	validator := authCfg.Validator()

	svc := controller.NewService(controller.Config{
		Validator: validator,
		Logger:    logger,
	})
	svc.RegisterWorker(controller.Worker{
		WorkerID:  *workerID,
		Hostname:  *workerHost,
		BaseURL:   *workerBaseURL,
		Available: true,
	})

	logger.Info(
		"controller configured",
		"auth_mode", validator.Mode(),
		"worker_id", *workerID,
		"worker_hostname", *workerHost,
		"worker_base_url", *workerBaseURL,
	)

	ctx, stop := cmdutil.SignalContext()
	defer stop()

	return cmdutil.RunServer(ctx, cmdutil.ServerConfig{
		Name:    "controller",
		Addr:    *listenAddr,
		Handler: svc.Handler(),
		Logger:  logger,
	})
}
