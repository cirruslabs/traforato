package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/fedor/traforato/internal/broker"
	"github.com/fedor/traforato/internal/cmdutil"
	"github.com/fedor/traforato/internal/sandboxid"
)

const (
	envBrokerListenAddr  = "TRAFORATO_BROKER_LISTEN_ADDR"
	envBrokerID          = "TRAFORATO_BROKER_ID"
	envBrokerWorkerID    = "TRAFORATO_BROKER_WORKER_ID"
	envBrokerWorkerHost  = "TRAFORATO_BROKER_WORKER_HOSTNAME"
	envBrokerWorkerBase  = "TRAFORATO_BROKER_WORKER_BASE_URL"
	envBrokerWorkerSKU   = "TRAFORATO_BROKER_WORKER_HARDWARE_SKU"
	defaultBrokerAddress = ":8080"
	defaultBrokerID      = "broker_local"
	defaultWorkerID      = "worker_local"
	defaultWorkerHost    = "localhost"
	defaultWorkerBaseURL = "http://localhost:8081"
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
	workerID := fs.String("worker-id", cmdutil.EnvOrDefault(envBrokerWorkerID, defaultWorkerID), "registered worker ID")
	workerHost := fs.String("worker-hostname", cmdutil.EnvOrDefault(envBrokerWorkerHost, defaultWorkerHost), "registered worker hostname")
	workerBaseURL := fs.String("worker-base-url", cmdutil.EnvOrDefault(envBrokerWorkerBase, defaultWorkerBaseURL), "registered worker base URL")
	workerHardwareSKU := fs.String("worker-hardware-sku", os.Getenv(envBrokerWorkerSKU), "registered worker hardware SKU")
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
	if err := sandboxid.ValidateComponentID(*workerID); err != nil {
		return fmt.Errorf("invalid worker-id: %w", err)
	}

	logger := cmdutil.NewLogger("broker")
	validator := authCfg.Validator()

	svc := broker.NewService(broker.Config{
		BrokerID:  *brokerID,
		Validator: validator,
		Logger:    logger,
	})
	svc.RegisterWorker(broker.Worker{
		WorkerID:    *workerID,
		Hostname:    *workerHost,
		BaseURL:     *workerBaseURL,
		HardwareSKU: *workerHardwareSKU,
		Available:   true,
	})

	logger.Info(
		"broker configured",
		"auth_mode", validator.Mode(),
		"broker_id", *brokerID,
		"worker_id", *workerID,
		"worker_hostname", *workerHost,
		"worker_base_url", *workerBaseURL,
		"worker_hardware_sku", *workerHardwareSKU,
	)

	ctx, stop := cmdutil.SignalContext()
	defer stop()

	return cmdutil.RunServer(ctx, cmdutil.ServerConfig{
		Name:    "broker",
		Addr:    *listenAddr,
		Handler: svc.Handler(),
		Logger:  logger,
	})
}
