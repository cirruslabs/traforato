package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/fedor/traforato/internal/cmdutil"
	"github.com/fedor/traforato/internal/controller"
	"github.com/fedor/traforato/internal/warm"
	"github.com/fedor/traforato/internal/worker"
)

const (
	envDevWorkerConfigPath     = "TRAFORATO_DEV_WORKER_CONFIG"
	envDevControllerListenAddr = "TRAFORATO_DEV_CONTROLLER_LISTEN_ADDR"
	envDevWorkerListenAddr     = "TRAFORATO_DEV_WORKER_LISTEN_ADDR"
	envDevWorkerBaseURL        = "TRAFORATO_DEV_WORKER_BASE_URL"
	envDevWorkerID             = "TRAFORATO_DEV_WORKER_ID"
	envDevWorkerHost           = "TRAFORATO_DEV_WORKER_HOSTNAME"
	envDevWorkerTotalCores     = "TRAFORATO_DEV_WORKER_TOTAL_CORES"
	envDevWorkerTotalMemoryMiB = "TRAFORATO_DEV_WORKER_TOTAL_MEMORY_MIB"
	envDevWorkerMaxLive        = "TRAFORATO_DEV_WORKER_MAX_LIVE_SANDBOXES"
	envDevWorkerDefaultTTL     = "TRAFORATO_DEV_WORKER_DEFAULT_TTL"

	defaultDevControllerListenAddr = ":8080"
	defaultDevWorkerListenAddr     = ":8081"
	defaultDevWorkerID             = "worker-local"
	defaultDevWorkerHost           = "localhost"
	defaultDevWorkerTTL            = 30 * time.Minute
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "dev: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("dev", flag.ContinueOnError)

	workerConfigPath := fs.String("file", cmdutil.EnvOrDefault(envDevWorkerConfigPath, ""), "worker YAML config file")
	controllerListenAddr := fs.String("controller-listen", cmdutil.EnvOrDefault(envDevControllerListenAddr, defaultDevControllerListenAddr), "controller listen address")
	workerListenAddr := fs.String("worker-listen", cmdutil.EnvOrDefault(envDevWorkerListenAddr, defaultDevWorkerListenAddr), "worker listen address")
	workerBaseURL := fs.String("worker-base-url", os.Getenv(envDevWorkerBaseURL), "worker base URL advertised by controller (default: derived from worker-listen)")
	workerID := fs.String("worker-id", cmdutil.EnvOrDefault(envDevWorkerID, defaultDevWorkerID), "worker ID")
	workerHost := fs.String("worker-hostname", cmdutil.EnvOrDefault(envDevWorkerHost, defaultDevWorkerHost), "worker hostname used for sandbox IDs")
	totalCores := fs.Int("total-cores", cmdutil.IntEnvOrDefault(envDevWorkerTotalCores, 0), "worker CPU capacity (0 = runtime default)")
	totalMemoryMiB := fs.Int("total-memory-mib", cmdutil.IntEnvOrDefault(envDevWorkerTotalMemoryMiB, 0), "worker memory capacity in MiB (0 = derived default)")
	maxLiveSandboxes := fs.Int("max-live-sandboxes", cmdutil.IntEnvOrDefault(envDevWorkerMaxLive, 0), "maximum concurrent sandboxes (0 = platform default)")
	defaultTTL := fs.Duration("default-ttl", cmdutil.DurationEnvOrDefault(envDevWorkerDefaultTTL, defaultDevWorkerTTL), "default sandbox lease duration")
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

	if *workerBaseURL == "" {
		*workerBaseURL = deriveWorkerBaseURL(*workerListenAddr)
	}

	workerCfg, err := cmdutil.LoadWorkerConfig(*workerConfigPath, cmdutil.WorkerFileConfig{
		WorkerID:         *workerID,
		Hostname:         *workerHost,
		TotalCores:       *totalCores,
		TotalMemoryMiB:   *totalMemoryMiB,
		MaxLiveSandboxes: *maxLiveSandboxes,
		DefaultTTL:       *defaultTTL,
	})
	if err != nil {
		return err
	}

	devLogger := cmdutil.NewLogger("dev")
	controllerLogger := devLogger.With("component", "controller")
	workerLogger, err := cmdutil.NewLoggerWithConfig("worker", workerCfg.Log)
	if err != nil {
		return err
	}

	controllerValidator := authCfg.Validator()
	workerValidator := authCfg.Validator()

	controllerSvc := controller.NewService(controller.Config{
		Validator: controllerValidator,
		Logger:    controllerLogger,
	})
	controllerSvc.RegisterWorker(controller.Worker{
		WorkerID:    workerCfg.WorkerID,
		Hostname:    workerCfg.Hostname,
		BaseURL:     *workerBaseURL,
		HardwareSKU: workerCfg.HardwareSKU,
		Available:   true,
	})

	warmPool := warm.NewManager(time.Now, nil)
	for _, target := range workerCfg.PrePullTargets() {
		tuple := warm.Tuple{
			Virtualization: target.Virtualization,
			Image:          target.Image,
			CPU:            target.CPU,
		}
		warmPool.SetTupleConfig(tuple, target.TargetCount, target.WarmupScript, target.WarmupTimeoutSeconds)
		if err := warmPool.EnsureReady(tuple); err != nil {
			workerLogger.Warn("failed to pre-pull image", "image", target.Image, "virtualization", target.Virtualization, "cpu", target.CPU, "error", err)
		}
	}

	workerSvc := worker.NewService(worker.Config{
		WorkerID:         workerCfg.WorkerID,
		Hostname:         workerCfg.Hostname,
		Validator:        workerValidator,
		Logger:           workerLogger,
		TotalCores:       workerCfg.TotalCores,
		TotalMemoryMiB:   workerCfg.TotalMemoryMiB,
		MaxLiveSandboxes: workerCfg.MaxLiveSandboxes,
		DefaultTTL:       workerCfg.DefaultTTL,
		WarmPool:         warmPool,
	})

	devLogger.Info(
		"dev environment configured",
		"auth_mode", controllerValidator.Mode(),
		"controller_addr", *controllerListenAddr,
		"worker_addr", *workerListenAddr,
		"worker_id", workerCfg.WorkerID,
		"worker_hostname", workerCfg.Hostname,
		"worker_base_url", *workerBaseURL,
		"hardware_sku", workerCfg.HardwareSKU,
		"pre_pull_images", len(workerCfg.PrePullTargets()),
	)

	signalCtx, stop := cmdutil.SignalContext()
	defer stop()

	runCtx, cancel := context.WithCancel(signalCtx)
	defer cancel()

	errCh := make(chan error, 2)
	go func() {
		errCh <- cmdutil.RunServer(runCtx, cmdutil.ServerConfig{
			Name:    "controller",
			Addr:    *controllerListenAddr,
			Handler: controllerSvc.Handler(),
			Logger:  controllerLogger,
		})
	}()
	go func() {
		errCh <- cmdutil.RunServer(runCtx, cmdutil.ServerConfig{
			Name:    "worker",
			Addr:    *workerListenAddr,
			Handler: workerSvc.Handler(),
			Logger:  workerLogger,
		})
	}()

	var firstErr error
	for i := 0; i < 2; i++ {
		err := <-errCh
		if err != nil && firstErr == nil {
			firstErr = err
			cancel()
		}
	}

	return firstErr
}

func deriveWorkerBaseURL(listenAddr string) string {
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil || port == "" {
		return "http://localhost:8081"
	}

	switch host {
	case "", "0.0.0.0", "::":
		host = "localhost"
	}

	return "http://" + net.JoinHostPort(host, port)
}
