package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/fedor/traforato/internal/cmdutil"
	"github.com/fedor/traforato/internal/sandboxid"
	"github.com/fedor/traforato/internal/warm"
	"github.com/fedor/traforato/internal/worker"
)

const (
	envWorkerConfigPath     = "TRAFORATO_WORKER_CONFIG"
	envWorkerListenAddr     = "TRAFORATO_WORKER_LISTEN_ADDR"
	envWorkerBrokerID       = "TRAFORATO_WORKER_BROKER_ID"
	envWorkerBrokerControl  = "TRAFORATO_WORKER_BROKER_CONTROL_URL"
	envWorkerID             = "TRAFORATO_WORKER_ID"
	envWorkerHost           = "TRAFORATO_WORKER_HOSTNAME"
	envWorkerTotalCores     = "TRAFORATO_WORKER_TOTAL_CORES"
	envWorkerTotalMemoryMiB = "TRAFORATO_WORKER_TOTAL_MEMORY_MIB"
	envWorkerMaxLive        = "TRAFORATO_WORKER_MAX_LIVE_SANDBOXES"
	envWorkerDefaultTTL     = "TRAFORATO_WORKER_DEFAULT_TTL"
	envWorkerRegHeartbeat   = "TRAFORATO_WORKER_REGISTRATION_HEARTBEAT"
	envWorkerRegJitter      = "TRAFORATO_WORKER_REGISTRATION_JITTER_PERCENT"

	defaultWorkerListenAddr      = ":8081"
	defaultBrokerID              = "broker_local"
	defaultWorkerID              = "worker_local"
	defaultWorkerHost            = "localhost"
	defaultWorkerTTL             = 30 * time.Minute
	defaultRegistrationHeartbeat = 30 * time.Second
	defaultRegistrationJitter    = 20
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "worker: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("worker", flag.ContinueOnError)

	configPath := fs.String("file", cmdutil.EnvOrDefault(envWorkerConfigPath, ""), "worker YAML config file")
	listenAddr := fs.String("listen", cmdutil.EnvOrDefault(envWorkerListenAddr, defaultWorkerListenAddr), "worker listen address")
	brokerID := fs.String("broker-id", cmdutil.EnvOrDefault(envWorkerBrokerID, defaultBrokerID), "broker ID used for sandbox IDs")
	brokerControlURL := fs.String("broker-control-url", cmdutil.EnvOrDefault(envWorkerBrokerControl, ""), "broker base URL used for placement retries and VM callbacks")
	workerID := fs.String("worker-id", cmdutil.EnvOrDefault(envWorkerID, defaultWorkerID), "worker ID used for sandbox IDs")
	workerHost := fs.String("hostname", cmdutil.EnvOrDefault(envWorkerHost, defaultWorkerHost), "worker hostname")
	totalCores := fs.Int("total-cores", cmdutil.IntEnvOrDefault(envWorkerTotalCores, 0), "worker CPU capacity (0 = runtime default)")
	totalMemoryMiB := fs.Int("total-memory-mib", cmdutil.IntEnvOrDefault(envWorkerTotalMemoryMiB, 0), "worker memory capacity in MiB (0 = derived default)")
	maxLiveSandboxes := fs.Int("max-live-sandboxes", cmdutil.IntEnvOrDefault(envWorkerMaxLive, 0), "maximum concurrent sandboxes (0 = platform default)")
	defaultTTL := fs.Duration("default-ttl", cmdutil.DurationEnvOrDefault(envWorkerDefaultTTL, defaultWorkerTTL), "default sandbox lease duration")
	registrationHeartbeat := fs.Duration("registration-heartbeat", cmdutil.DurationEnvOrDefault(envWorkerRegHeartbeat, defaultRegistrationHeartbeat), "worker registration heartbeat interval")
	registrationJitter := fs.Int("registration-jitter-percent", cmdutil.IntEnvOrDefault(envWorkerRegJitter, defaultRegistrationJitter), "worker registration heartbeat jitter percentage")
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

	cfg, err := cmdutil.LoadWorkerConfig(*configPath, cmdutil.WorkerFileConfig{
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
	if err := sandboxid.ValidateComponentID(cfg.BrokerID); err != nil {
		return fmt.Errorf("invalid broker-id: %w", err)
	}
	if err := sandboxid.ValidateComponentID(cfg.WorkerID); err != nil {
		return fmt.Errorf("invalid worker-id: %w", err)
	}

	logger, err := cmdutil.NewLoggerWithConfig("worker", cfg.Log)
	if err != nil {
		return err
	}

	validator := authCfg.Validator()
	warmPool := warm.NewManager(time.Now, nil)
	for _, target := range cfg.PrePullTargets() {
		tuple := warm.Tuple{
			Virtualization: target.Virtualization,
			Image:          target.Image,
			CPU:            target.CPU,
		}
		warmPool.SetTupleConfig(tuple, target.TargetCount, target.WarmupScript, target.WarmupTimeoutSeconds)
		if err := warmPool.EnsureReady(tuple); err != nil {
			logger.Warn("failed to pre-pull image", "image", target.Image, "virtualization", target.Virtualization, "cpu", target.CPU, "error", err)
		}
	}
	advertiseURL := deriveWorkerBaseURL(*listenAddr, cfg.Hostname)

	svc := worker.NewService(worker.Config{
		WorkerID:                  cfg.WorkerID,
		BrokerID:                  cfg.BrokerID,
		BrokerControlURL:          cfg.BrokerControlURL,
		Hostname:                  cfg.Hostname,
		AdvertiseURL:              advertiseURL,
		HardwareSKU:               cfg.HardwareSKU,
		Validator:                 validator,
		Logger:                    logger,
		TotalCores:                cfg.TotalCores,
		TotalMemoryMiB:            cfg.TotalMemoryMiB,
		MaxLiveSandboxes:          cfg.MaxLiveSandboxes,
		DefaultTTL:                cfg.DefaultTTL,
		RegistrationHeartbeat:     cfg.RegistrationHeartbeat,
		RegistrationJitterPercent: cfg.RegistrationJitterPercent,
		WarmPool:                  warmPool,
		InternalJWTSecret:         authCfg.Secret,
		InternalJWTIssuer:         authCfg.Issuer,
		InternalJWTAudience:       "traforato-internal",
	})

	logger.Info(
		"worker configured",
		"auth_mode", validator.Mode(),
		"broker_id", cfg.BrokerID,
		"worker_id", cfg.WorkerID,
		"hostname", cfg.Hostname,
		"advertise_url", advertiseURL,
		"broker_control_url", cfg.BrokerControlURL,
		"hardware_sku", cfg.HardwareSKU,
		"total_cores", cfg.TotalCores,
		"total_memory_mib", cfg.TotalMemoryMiB,
		"max_live_sandboxes", cfg.MaxLiveSandboxes,
		"default_ttl", cfg.DefaultTTL.String(),
		"registration_heartbeat", cfg.RegistrationHeartbeat.String(),
		"registration_jitter_percent", cfg.RegistrationJitterPercent,
		"pre_pull_images", len(cfg.PrePullTargets()),
	)

	ctx, stop := cmdutil.SignalContext()
	defer stop()
	if err := svc.RegisterInitial(ctx); err != nil {
		return fmt.Errorf("initial worker registration failed: %w", err)
	}
	go svc.RunRegistrationLoop(ctx)

	runErr := cmdutil.RunServer(ctx, cmdutil.ServerConfig{
		Name:    "worker",
		Addr:    *listenAddr,
		Handler: svc.Handler(),
		Logger:  logger,
	})
	deregisterCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	svc.DeregisterWorker(deregisterCtx)
	cancel()
	return runErr
}

func deriveWorkerBaseURL(listenAddr, hostname string) string {
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil || port == "" {
		port = "8081"
	}
	switch host {
	case "", "0.0.0.0", "::":
		host = strings.TrimSpace(hostname)
	}
	if host == "" {
		host = "localhost"
	}
	return "http://" + net.JoinHostPort(host, port)
}
