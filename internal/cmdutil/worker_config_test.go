package cmdutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadWorkerConfigMergeAndOverride(t *testing.T) {
	t.Parallel()

	defaults := WorkerFileConfig{
		BrokerID:         "broker_local",
		WorkerID:         "worker-a",
		Hostname:         "worker-a.local",
		TotalCores:       4,
		TotalMemoryMiB:   4096,
		MaxLiveSandboxes: 2,
		DefaultTTL:       30 * time.Minute,
	}

	configPath := filepath.Join(t.TempDir(), "worker.yaml")
	configBody := `
broker-id: broker_beta
broker-control-url: http://broker.internal:8080
virtualization: vetu
hostname: worker-b.local
hardware-sku: gpu-a100
max-live-sandboxes: 7
default-ttl: 45m
registration-heartbeat: 25s
registration-jitter-percent: 15
log:
  file: /tmp/traforato-worker.log
  rotate-size: 100 MB
  max-rotations: 10
pre-pull:
  images:
    - ghcr.io/cirruslabs/ubuntu-runner-amd64:24.04
`
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadWorkerConfig(configPath, defaults)
	if err != nil {
		t.Fatalf("LoadWorkerConfig() error = %v", err)
	}

	if cfg.WorkerID != defaults.WorkerID {
		t.Fatalf("WorkerID mismatch: got %q want %q", cfg.WorkerID, defaults.WorkerID)
	}
	if cfg.BrokerID != "broker_beta" {
		t.Fatalf("BrokerID mismatch: got %q", cfg.BrokerID)
	}
	if cfg.BrokerControlURL != "http://broker.internal:8080" {
		t.Fatalf("BrokerControlURL mismatch: got %q", cfg.BrokerControlURL)
	}
	if cfg.Hostname != "worker-b.local" {
		t.Fatalf("Hostname mismatch: got %q", cfg.Hostname)
	}
	if cfg.HardwareSKU != "gpu-a100" {
		t.Fatalf("HardwareSKU mismatch: got %q", cfg.HardwareSKU)
	}
	if cfg.Virtualization != "vetu" {
		t.Fatalf("Virtualization mismatch: got %q", cfg.Virtualization)
	}
	if cfg.MaxLiveSandboxes != 7 {
		t.Fatalf("MaxLiveSandboxes mismatch: got %d", cfg.MaxLiveSandboxes)
	}
	if cfg.DefaultTTL != 45*time.Minute {
		t.Fatalf("DefaultTTL mismatch: got %s", cfg.DefaultTTL)
	}
	if cfg.RegistrationHeartbeat != 25*time.Second {
		t.Fatalf("RegistrationHeartbeat mismatch: got %s", cfg.RegistrationHeartbeat)
	}
	if cfg.RegistrationJitterPercent != 15 {
		t.Fatalf("RegistrationJitterPercent mismatch: got %d", cfg.RegistrationJitterPercent)
	}
	if cfg.Log.File != "/tmp/traforato-worker.log" {
		t.Fatalf("log.file mismatch: got %q", cfg.Log.File)
	}
	if cfg.Log.RotateSize != "100 MB" {
		t.Fatalf("log.rotate-size mismatch: got %q", cfg.Log.RotateSize)
	}
	if cfg.Log.MaxRotations != 10 {
		t.Fatalf("log.max-rotations mismatch: got %d", cfg.Log.MaxRotations)
	}
}

func TestLoadWorkerConfigUnknownFields(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "worker.yaml")
	if err := os.WriteFile(configPath, []byte("unknown-field: 1\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := LoadWorkerConfig(configPath, WorkerFileConfig{})
	if err == nil {
		t.Fatal("expected error for unknown fields")
	}
	if !strings.Contains(err.Error(), "unknown-field") {
		t.Fatalf("expected unknown field error, got %v", err)
	}
}

func TestPrePullTargetsDefaultsAndDedupe(t *testing.T) {
	t.Parallel()

	cfg := WorkerFileConfig{
		PrePull: WorkerPrePullConfig{
			Images: []string{
				"ubuntu:24.04",
				" ",
				"ubuntu:24.04",
				"alpine:3.20",
			},
		},
	}

	targets := cfg.PrePullTargets()
	if len(targets) != 2 {
		t.Fatalf("unexpected target count: got %d", len(targets))
	}
	if targets[0].Image != "ubuntu:24.04" || targets[1].Image != "alpine:3.20" {
		t.Fatalf("unexpected images: %+v", targets)
	}
	for _, target := range targets {
		if target.Virtualization != "vetu" {
			t.Fatalf("unexpected virtualization: %q", target.Virtualization)
		}
		if target.CPU != 1 {
			t.Fatalf("unexpected cpu: %d", target.CPU)
		}
		if target.TargetCount != 1 {
			t.Fatalf("unexpected target count: %d", target.TargetCount)
		}
	}
}

func TestParseRotateSizeToMiB(t *testing.T) {
	t.Parallel()

	got, err := parseRotateSizeToMiB("128 MB")
	if err != nil {
		t.Fatalf("parseRotateSizeToMiB() error = %v", err)
	}
	if got != 128 {
		t.Fatalf("unexpected size MiB: got %d want %d", got, 128)
	}

	if _, err := parseRotateSizeToMiB("invalid"); err == nil {
		t.Fatal("expected error for invalid size")
	}
}
