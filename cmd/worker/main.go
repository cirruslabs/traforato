package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/fedor/traforetto/internal/cmdutil"
	"github.com/fedor/traforetto/internal/worker"
)

const (
	envWorkerListenAddr     = "TRAFORETTO_WORKER_LISTEN_ADDR"
	envWorkerID             = "TRAFORETTO_WORKER_ID"
	envWorkerHost           = "TRAFORETTO_WORKER_HOSTNAME"
	envWorkerTotalCores     = "TRAFORETTO_WORKER_TOTAL_CORES"
	envWorkerTotalMemoryMiB = "TRAFORETTO_WORKER_TOTAL_MEMORY_MIB"
	envWorkerMaxLive        = "TRAFORETTO_WORKER_MAX_LIVE_SANDBOXES"
	envWorkerDefaultTTL     = "TRAFORETTO_WORKER_DEFAULT_TTL"

	defaultWorkerListenAddr = ":8081"
	defaultWorkerID         = "worker-local"
	defaultWorkerHost       = "localhost"
	defaultWorkerTTL        = 30 * time.Minute
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "worker: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("worker", flag.ContinueOnError)

	listenAddr := fs.String("listen", cmdutil.EnvOrDefault(envWorkerListenAddr, defaultWorkerListenAddr), "worker listen address")
	workerID := fs.String("worker-id", cmdutil.EnvOrDefault(envWorkerID, defaultWorkerID), "worker ID")
	workerHost := fs.String("hostname", cmdutil.EnvOrDefault(envWorkerHost, defaultWorkerHost), "worker hostname used for sandbox IDs")
	totalCores := fs.Int("total-cores", cmdutil.IntEnvOrDefault(envWorkerTotalCores, 0), "worker CPU capacity (0 = runtime default)")
	totalMemoryMiB := fs.Int("total-memory-mib", cmdutil.IntEnvOrDefault(envWorkerTotalMemoryMiB, 0), "worker memory capacity in MiB (0 = derived default)")
	maxLiveSandboxes := fs.Int("max-live-sandboxes", cmdutil.IntEnvOrDefault(envWorkerMaxLive, 0), "maximum concurrent sandboxes (0 = platform default)")
	defaultTTL := fs.Duration("default-ttl", cmdutil.DurationEnvOrDefault(envWorkerDefaultTTL, defaultWorkerTTL), "default sandbox lease duration")
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

	logger := cmdutil.NewLogger("worker")
	validator := authCfg.Validator()

	svc := worker.NewService(worker.Config{
		WorkerID:         *workerID,
		Hostname:         *workerHost,
		Validator:        validator,
		Logger:           logger,
		TotalCores:       *totalCores,
		TotalMemoryMiB:   *totalMemoryMiB,
		MaxLiveSandboxes: *maxLiveSandboxes,
		DefaultTTL:       *defaultTTL,
	})

	logger.Info(
		"worker configured",
		"auth_mode", validator.Mode(),
		"worker_id", *workerID,
		"hostname", *workerHost,
		"total_cores", *totalCores,
		"total_memory_mib", *totalMemoryMiB,
		"max_live_sandboxes", *maxLiveSandboxes,
		"default_ttl", defaultTTL.String(),
	)

	ctx, stop := cmdutil.SignalContext()
	defer stop()

	return cmdutil.RunServer(ctx, cmdutil.ServerConfig{
		Name:    "worker",
		Addr:    *listenAddr,
		Handler: svc.Handler(),
		Logger:  logger,
	})
}
