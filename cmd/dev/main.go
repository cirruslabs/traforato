package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/fedor/traforato/internal/broker"
	"github.com/fedor/traforato/internal/cmdutil"
	"github.com/fedor/traforato/internal/sandboxid"
	"github.com/fedor/traforato/internal/warm"
	"github.com/fedor/traforato/internal/worker"
)

const (
	envDevWorkerConfigPath     = "TRAFORATO_DEV_WORKER_CONFIG"
	envDevBrokerListenAddr     = "TRAFORATO_DEV_BROKER_LISTEN_ADDR"
	envDevBrokerID             = "TRAFORATO_DEV_BROKER_ID"
	envDevBrokerControlURL     = "TRAFORATO_DEV_BROKER_CONTROL_URL"
	envDevWorkerListenAddr     = "TRAFORATO_DEV_WORKER_LISTEN_ADDR"
	envDevWorkerBaseURL        = "TRAFORATO_DEV_WORKER_BASE_URL"
	envDevWorkerID             = "TRAFORATO_DEV_WORKER_ID"
	envDevWorkerHost           = "TRAFORATO_DEV_WORKER_HOSTNAME"
	envDevWorkerTotalCores     = "TRAFORATO_DEV_WORKER_TOTAL_CORES"
	envDevWorkerTotalMemoryMiB = "TRAFORATO_DEV_WORKER_TOTAL_MEMORY_MIB"
	envDevWorkerMaxLive        = "TRAFORATO_DEV_WORKER_MAX_LIVE_SANDBOXES"
	envDevWorkerDefaultTTL     = "TRAFORATO_DEV_WORKER_DEFAULT_TTL"
	envDevWorkerRegHeartbeat   = "TRAFORATO_DEV_WORKER_REGISTRATION_HEARTBEAT"
	envDevWorkerRegJitter      = "TRAFORATO_DEV_WORKER_REGISTRATION_JITTER_PERCENT"

	defaultDevBrokerListenAddr = ":8080"
	defaultDevWorkerListenAddr = ":8081"
	defaultDevBrokerID         = "broker_local"
	defaultDevWorkerID         = "worker_local"
	defaultDevWorkerHost       = "localhost"
	defaultDevWorkerTTL        = 30 * time.Minute
	defaultDevRegHeartbeat     = 30 * time.Second
	defaultDevRegJitter        = 20
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
	brokerListenAddr := fs.String("broker-listen", cmdutil.EnvOrDefault(envDevBrokerListenAddr, defaultDevBrokerListenAddr), "broker listen address")
	brokerID := fs.String("broker-id", cmdutil.EnvOrDefault(envDevBrokerID, defaultDevBrokerID), "broker ID used for sandbox IDs")
	brokerControlURL := fs.String("broker-control-url", cmdutil.EnvOrDefault(envDevBrokerControlURL, ""), "broker base URL used by worker for placement retries and VM callbacks")
	workerListenAddr := fs.String("worker-listen", cmdutil.EnvOrDefault(envDevWorkerListenAddr, defaultDevWorkerListenAddr), "worker listen address")
	workerBaseURL := fs.String("worker-base-url", os.Getenv(envDevWorkerBaseURL), "worker base URL advertised by broker (default: derived from worker-listen)")
	workerID := fs.String("worker-id", cmdutil.EnvOrDefault(envDevWorkerID, defaultDevWorkerID), "worker ID used for sandbox IDs")
	workerHost := fs.String("worker-hostname", cmdutil.EnvOrDefault(envDevWorkerHost, defaultDevWorkerHost), "worker hostname")
	totalCores := fs.Int("total-cores", cmdutil.IntEnvOrDefault(envDevWorkerTotalCores, 0), "worker CPU capacity (0 = runtime default)")
	totalMemoryMiB := fs.Int("total-memory-mib", cmdutil.IntEnvOrDefault(envDevWorkerTotalMemoryMiB, 0), "worker memory capacity in MiB (0 = derived default)")
	maxLiveSandboxes := fs.Int("max-live-sandboxes", cmdutil.IntEnvOrDefault(envDevWorkerMaxLive, 0), "maximum concurrent sandboxes (0 = platform default)")
	defaultTTL := fs.Duration("default-ttl", cmdutil.DurationEnvOrDefault(envDevWorkerDefaultTTL, defaultDevWorkerTTL), "default sandbox lease duration")
	registrationHeartbeat := fs.Duration("registration-heartbeat", cmdutil.DurationEnvOrDefault(envDevWorkerRegHeartbeat, defaultDevRegHeartbeat), "worker registration heartbeat interval")
	registrationJitter := fs.Int("registration-jitter-percent", cmdutil.IntEnvOrDefault(envDevWorkerRegJitter, defaultDevRegJitter), "worker registration heartbeat jitter percentage")
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
	if *brokerControlURL == "" {
		*brokerControlURL = deriveBrokerBaseURL(*brokerListenAddr)
	}

	workerCfg, err := cmdutil.LoadWorkerConfig(*workerConfigPath, cmdutil.WorkerFileConfig{
		BrokerID:                  *brokerID,
		BrokerControlURL:          *brokerControlURL,
		WorkerID:                  *workerID,
		Hostname:                  *workerHost,
		TotalCores:                *totalCores,
		TotalMemoryMiB:            *totalMemoryMiB,
		MaxLiveSandboxes:          *maxLiveSandboxes,
		DefaultTTL:                *defaultTTL,
		RegistrationHeartbeat:     *registrationHeartbeat,
		RegistrationJitterPercent: *registrationJitter,
	})
	if err != nil {
		return err
	}
	if err := sandboxid.ValidateComponentID(workerCfg.BrokerID); err != nil {
		return fmt.Errorf("invalid broker-id: %w", err)
	}
	if err := sandboxid.ValidateComponentID(workerCfg.WorkerID); err != nil {
		return fmt.Errorf("invalid worker-id: %w", err)
	}

	devLogger := cmdutil.NewLogger("dev")
	brokerLogger := devLogger.With("component", "broker")
	workerLogger, err := cmdutil.NewLoggerWithConfig("worker", workerCfg.Log)
	if err != nil {
		return err
	}

	brokerValidator := authCfg.Validator()
	workerValidator := authCfg.Validator()

	brokerSvc := broker.NewService(broker.Config{
		BrokerID:            workerCfg.BrokerID,
		Validator:           brokerValidator,
		Logger:              brokerLogger,
		PlacementRetryMax:   2,
		InternalJWTSecret:   authCfg.Secret,
		InternalJWTIssuer:   authCfg.Issuer,
		InternalJWTAudience: "traforato-internal",
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
		WorkerID:                  workerCfg.WorkerID,
		BrokerID:                  workerCfg.BrokerID,
		BrokerControlURL:          workerCfg.BrokerControlURL,
		Hostname:                  workerCfg.Hostname,
		AdvertiseURL:              *workerBaseURL,
		HardwareSKU:               workerCfg.HardwareSKU,
		Validator:                 workerValidator,
		Logger:                    workerLogger,
		TotalCores:                workerCfg.TotalCores,
		TotalMemoryMiB:            workerCfg.TotalMemoryMiB,
		MaxLiveSandboxes:          workerCfg.MaxLiveSandboxes,
		DefaultTTL:                workerCfg.DefaultTTL,
		RegistrationHeartbeat:     workerCfg.RegistrationHeartbeat,
		RegistrationJitterPercent: workerCfg.RegistrationJitterPercent,
		WarmPool:                  warmPool,
		InternalJWTSecret:         authCfg.Secret,
		InternalJWTIssuer:         authCfg.Issuer,
		InternalJWTAudience:       "traforato-internal",
	})

	devLogger.Info(
		"dev environment configured",
		"auth_mode", brokerValidator.Mode(),
		"broker_addr", *brokerListenAddr,
		"broker_id", workerCfg.BrokerID,
		"worker_addr", *workerListenAddr,
		"worker_id", workerCfg.WorkerID,
		"worker_hostname", workerCfg.Hostname,
		"worker_base_url", *workerBaseURL,
		"broker_control_url", workerCfg.BrokerControlURL,
		"hardware_sku", workerCfg.HardwareSKU,
		"registration_heartbeat", workerCfg.RegistrationHeartbeat.String(),
		"registration_jitter_percent", workerCfg.RegistrationJitterPercent,
		"pre_pull_images", len(workerCfg.PrePullTargets()),
	)

	signalCtx, stop := cmdutil.SignalContext()
	defer stop()

	runCtx, cancel := context.WithCancel(signalCtx)
	defer cancel()
	go brokerSvc.RunLeaseSweeper(runCtx)
	go workerSvc.RunRegistrationLoop(runCtx)

	errCh := make(chan error, 2)
	go func() {
		errCh <- cmdutil.RunServer(runCtx, cmdutil.ServerConfig{
			Name:    "broker",
			Addr:    *brokerListenAddr,
			Handler: brokerSvc.Handler(),
			Logger:  brokerLogger,
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

	deregisterCtx, deregisterCancel := context.WithTimeout(context.Background(), 2*time.Second)
	workerSvc.DeregisterWorker(deregisterCtx)
	deregisterCancel()

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

func deriveBrokerBaseURL(listenAddr string) string {
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil || port == "" {
		return "http://localhost:8080"
	}

	switch host {
	case "", "0.0.0.0", "::":
		host = "localhost"
	}

	return "http://" + net.JoinHostPort(host, port)
}
