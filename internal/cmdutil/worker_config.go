package cmdutil

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
	"gopkg.in/yaml.v3"
)

type WorkerFileConfig struct {
	WorkerID         string              `yaml:"worker-id"`
	Hostname         string              `yaml:"hostname"`
	HardwareSKU      string              `yaml:"hardware-sku"`
	Virtualization   string              `yaml:"virtualization"`
	TotalCores       int                 `yaml:"total-cores"`
	TotalMemoryMiB   int                 `yaml:"total-memory-mib"`
	MaxLiveSandboxes int                 `yaml:"max-live-sandboxes"`
	DefaultTTL       time.Duration       `yaml:"default-ttl"`
	Log              WorkerLogConfig     `yaml:"log"`
	PrePull          WorkerPrePullConfig `yaml:"pre-pull"`
}

type WorkerLogConfig struct {
	Level        string `yaml:"level"`
	File         string `yaml:"file"`
	RotateSize   string `yaml:"rotate-size"`
	MaxRotations int    `yaml:"max-rotations"`
}

type WorkerPrePullConfig struct {
	Images               []string `yaml:"images"`
	WarmupScript         string   `yaml:"warmup-script"`
	WarmupTimeoutSeconds int      `yaml:"warmup-timeout-seconds"`
}

type WorkerPrePullTarget struct {
	Image                string
	Virtualization       string
	CPU                  int
	TargetCount          int
	WarmupScript         string
	WarmupTimeoutSeconds int
}

func LoadWorkerConfig(path string, defaults WorkerFileConfig) (WorkerFileConfig, error) {
	cfg := defaults
	if strings.TrimSpace(path) == "" {
		return cfg, nil
	}

	configBytes, err := os.ReadFile(path)
	if err != nil {
		return WorkerFileConfig{}, fmt.Errorf("read worker config %q: %w", path, err)
	}

	decoder := yaml.NewDecoder(bytes.NewReader(configBytes))
	decoder.KnownFields(true)

	if err := decoder.Decode(&cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return cfg, nil
		}
		return WorkerFileConfig{}, fmt.Errorf("decode worker config %q: %w", path, err)
	}

	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return WorkerFileConfig{}, fmt.Errorf("decode worker config %q: multiple YAML documents are not supported", path)
	} else if !errors.Is(err, io.EOF) {
		return WorkerFileConfig{}, fmt.Errorf("decode worker config %q: %w", path, err)
	}

	return cfg, nil
}

func (cfg WorkerFileConfig) PrePullTargets() []WorkerPrePullTarget {
	if len(cfg.PrePull.Images) == 0 {
		return nil
	}

	virtualization := strings.TrimSpace(cfg.Virtualization)
	if virtualization == "" {
		virtualization = "vetu"
	}

	targets := make([]WorkerPrePullTarget, 0, len(cfg.PrePull.Images))
	seen := make(map[string]struct{}, len(cfg.PrePull.Images))
	for _, image := range cfg.PrePull.Images {
		image = strings.TrimSpace(image)
		if image == "" {
			continue
		}
		if _, exists := seen[image]; exists {
			continue
		}
		seen[image] = struct{}{}
		targets = append(targets, WorkerPrePullTarget{
			Image:                image,
			Virtualization:       virtualization,
			CPU:                  1,
			TargetCount:          1,
			WarmupScript:         cfg.PrePull.WarmupScript,
			WarmupTimeoutSeconds: cfg.PrePull.WarmupTimeoutSeconds,
		})
	}

	return targets
}

func NewLoggerWithConfig(service string, cfg WorkerLogConfig) (*slog.Logger, error) {
	if cfg.MaxRotations < 0 {
		return nil, fmt.Errorf("invalid log.max-rotations: must be >= 0")
	}

	opts := &slog.HandlerOptions{}
	if cfg.Level != "" {
		level, err := parseSlogLevel(cfg.Level)
		if err != nil {
			return nil, fmt.Errorf("invalid log.level: %w", err)
		}
		opts.Level = level
	}

	output := io.Writer(os.Stdout)
	if file := strings.TrimSpace(cfg.File); file != "" {
		maxSizeMiB, err := parseRotateSizeToMiB(cfg.RotateSize)
		if err != nil {
			return nil, fmt.Errorf("invalid log.rotate-size: %w", err)
		}
		output = &lumberjack.Logger{
			Filename:   file,
			MaxSize:    maxSizeMiB,
			MaxBackups: cfg.MaxRotations,
		}
	}

	return slog.New(slog.NewJSONHandler(output, opts)).With("service", service), nil
}

func parseSlogLevel(raw string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "trace", "debug":
		return slog.LevelDebug, nil
	case "", "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error", "fatal", "panic":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unsupported level %q", raw)
	}
}

func parseRotateSizeToMiB(raw string) (int, error) {
	if strings.TrimSpace(raw) == "" {
		return 0, nil
	}
	bytes, err := parseByteSize(raw)
	if err != nil {
		return 0, err
	}
	if bytes <= 0 {
		return 0, fmt.Errorf("must be > 0")
	}

	const mib = int64(1024 * 1024)
	sizeMiB := int((bytes + mib - 1) / mib)
	if sizeMiB <= 0 {
		sizeMiB = 1
	}
	return sizeMiB, nil
}

func parseByteSize(raw string) (int64, error) {
	normalized := strings.ToUpper(strings.TrimSpace(raw))
	normalized = strings.ReplaceAll(normalized, " ", "")
	if normalized == "" {
		return 0, fmt.Errorf("size is empty")
	}

	index := 0
	for index < len(normalized) && normalized[index] >= '0' && normalized[index] <= '9' {
		index++
	}
	if index == 0 {
		return 0, fmt.Errorf("missing numeric prefix in %q", raw)
	}

	value, err := strconv.ParseInt(normalized[:index], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number in %q: %w", raw, err)
	}
	unit := normalized[index:]
	multiplier, ok := byteSizeMultipliers[unit]
	if !ok {
		return 0, fmt.Errorf("unsupported unit %q", unit)
	}
	if value > 0 && value > (1<<63-1)/multiplier {
		return 0, fmt.Errorf("size overflow in %q", raw)
	}

	return value * multiplier, nil
}

var byteSizeMultipliers = map[string]int64{
	"":    1,
	"B":   1,
	"K":   1024,
	"KB":  1024,
	"KIB": 1024,
	"M":   1024 * 1024,
	"MB":  1024 * 1024,
	"MIB": 1024 * 1024,
	"G":   1024 * 1024 * 1024,
	"GB":  1024 * 1024 * 1024,
	"GIB": 1024 * 1024 * 1024,
	"T":   1024 * 1024 * 1024 * 1024,
	"TB":  1024 * 1024 * 1024 * 1024,
	"TIB": 1024 * 1024 * 1024 * 1024,
}
