package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/fedor/traforato/internal/broker"
	"github.com/fedor/traforato/internal/cmdutil"
	"github.com/fedor/traforato/internal/sandboxid"
)

const (
	envBrokerListenAddr = "TRAFORATO_BROKER_LISTEN_ADDR"
	envBrokerID         = "TRAFORATO_BROKER_ID"
	envBrokerRetryMax   = "TRAFORATO_BROKER_PLACEMENT_RETRY_MAX"
	envBrokerLeaseTTL   = "TRAFORATO_BROKER_WORKER_LEASE_TTL"
	envBrokerSweepEvery = "TRAFORATO_BROKER_WORKER_LEASE_SWEEP_INTERVAL"

	defaultBrokerAddress = ":8080"
	defaultBrokerID      = "broker_local"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "broker: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("broker", flag.ContinueOnError)

	listenAddr := fs.String("listen", cmdutil.EnvOrDefault(envBrokerListenAddr, defaultBrokerAddress), "broker listen address")
	brokerID := fs.String("broker-id", cmdutil.EnvOrDefault(envBrokerID, defaultBrokerID), "broker ID used for sandbox IDs")
	placementRetryMax := fs.Int("placement-retry-max", cmdutil.IntEnvOrDefault(envBrokerRetryMax, 2), "maximum broker placement retries for worker hot-potato redirects")
	workerLeaseTTL := fs.Duration("worker-lease-ttl", cmdutil.DurationEnvOrDefault(envBrokerLeaseTTL, 120*time.Second), "worker registration lease TTL")
	workerLeaseSweep := fs.Duration("worker-lease-sweep-interval", cmdutil.DurationEnvOrDefault(envBrokerSweepEvery, 10*time.Second), "worker lease sweep interval")
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
	if err := sandboxid.ValidateComponentID(*brokerID); err != nil {
		return fmt.Errorf("invalid broker-id: %w", err)
	}

	logger := cmdutil.NewLogger("broker")
	validator := authCfg.Validator()

	svc := broker.NewService(broker.Config{
		BrokerID:                 *brokerID,
		Validator:                validator,
		Logger:                   logger,
		PlacementRetryMax:        *placementRetryMax,
		InternalJWTSecret:        authCfg.Secret,
		InternalJWTIssuer:        authCfg.Issuer,
		InternalJWTAudience:      "traforato-internal",
		WorkerLeaseTTL:           *workerLeaseTTL,
		WorkerLeaseSweepInterval: *workerLeaseSweep,
	})

	logger.Info(
		"broker configured",
		"auth_mode", validator.Mode(),
		"broker_id", *brokerID,
		"worker_lease_ttl", workerLeaseTTL.String(),
		"worker_lease_sweep_interval", workerLeaseSweep.String(),
		"placement_retry_max", *placementRetryMax,
	)

	ctx, stop := cmdutil.SignalContext()
	defer stop()
	go svc.RunLeaseSweeper(ctx)

	return cmdutil.RunServer(ctx, cmdutil.ServerConfig{
		Name:    "broker",
		Addr:    *listenAddr,
		Handler: svc.Handler(),
		Logger:  logger,
	})
}
