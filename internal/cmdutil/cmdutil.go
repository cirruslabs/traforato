package cmdutil

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/fedor/traforetto/internal/auth"
)

const (
	DefaultJWTIssuer      = "traforetto"
	DefaultJWTAudience    = "traforetto-api"
	DefaultShutdownPeriod = 5 * time.Second

	EnvJWTSecret   = "TRAFORETTO_JWT_SECRET"
	EnvJWTIssuer   = "TRAFORETTO_JWT_ISSUER"
	EnvJWTAudience = "TRAFORETTO_JWT_AUDIENCE"
)

type AuthConfig struct {
	Secret   string
	Issuer   string
	Audience string
}

type ServerConfig struct {
	Name            string
	Addr            string
	Handler         http.Handler
	Logger          *slog.Logger
	ShutdownTimeout time.Duration
}

func EnvOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func IntEnvOrDefault(key string, fallback int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}

func DurationEnvOrDefault(key string, fallback time.Duration) time.Duration {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}
	return value
}

func BindAuthFlags(fs *flag.FlagSet) *AuthConfig {
	cfg := &AuthConfig{}
	fs.StringVar(&cfg.Secret, "jwt-secret", os.Getenv(EnvJWTSecret), "JWT secret (empty enables dev no-auth mode)")
	fs.StringVar(&cfg.Issuer, "jwt-issuer", EnvOrDefault(EnvJWTIssuer, DefaultJWTIssuer), "expected JWT issuer")
	fs.StringVar(&cfg.Audience, "jwt-audience", EnvOrDefault(EnvJWTAudience, DefaultJWTAudience), "expected JWT audience")
	return cfg
}

func (cfg *AuthConfig) Validator() *auth.Validator {
	if cfg == nil {
		return auth.NewValidator("", DefaultJWTIssuer, DefaultJWTAudience, nil)
	}
	return auth.NewValidator(cfg.Secret, cfg.Issuer, cfg.Audience, nil)
}

func NewLogger(service string) *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("service", service)
}

func SignalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func RunServer(ctx context.Context, cfg ServerConfig) error {
	if cfg.Handler == nil {
		return errors.New("server handler is required")
	}
	if cfg.Name == "" {
		cfg.Name = "server"
	}
	if cfg.Logger == nil {
		cfg.Logger = NewLogger(cfg.Name)
	}
	if cfg.ShutdownTimeout <= 0 {
		cfg.ShutdownTimeout = DefaultShutdownPeriod
	}

	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           cfg.Handler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		cfg.Logger.Info("listening", "addr", cfg.Addr)
		err := server.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("%s server failed: %w", cfg.Name, err)
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		cfg.Logger.Info("shutdown requested")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("%s server shutdown failed: %w", cfg.Name, err)
		}
		return <-errCh
	}
}
