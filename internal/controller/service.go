package controller

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/fedor/traforetto/internal/auth"
	"github.com/fedor/traforetto/internal/model"
	"github.com/fedor/traforetto/internal/sandboxid"
	"github.com/fedor/traforetto/internal/telemetry"
	"github.com/oklog/ulid/v2"
)

type Worker struct {
	WorkerID  string
	Hostname  string
	BaseURL   string
	Hash      string
	Available bool
}

type Config struct {
	Validator *auth.Validator
	Logger    *slog.Logger
	Telemetry *telemetry.Recorder
	Clock     func() time.Time
}

type Service struct {
	cfg Config

	mu            sync.RWMutex
	workersByHash map[string]Worker
	workers       []Worker
}

func NewService(cfg Config) *Service {
	if cfg.Validator == nil {
		cfg.Validator = auth.NewValidator("", "", "", nil)
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.Telemetry == nil {
		cfg.Telemetry = telemetry.NewRecorder(cfg.Validator.Mode())
	}
	authMode := "prod"
	authModeMetric := 1.0
	if cfg.Validator.Mode() == auth.ModeDev {
		authMode = "dev"
		authModeMetric = 0
		cfg.Logger.Warn("auth disabled: running controller in development no-auth mode", "auth_mode", authMode)
	}
	_ = cfg.Telemetry.SetGauge(telemetry.MetricServiceAuthMode, authModeMetric, nil)
	return &Service{
		cfg:           cfg,
		workersByHash: make(map[string]Worker),
	}
}

func (s *Service) RegisterWorker(worker Worker) {
	if worker.Hash == "" {
		worker.Hash = sandboxid.WorkerHash(worker.Hostname)
	}
	if !worker.Available {
		worker.Available = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	s.workersByHash[worker.Hash] = worker
	replaced := false
	for i := range s.workers {
		if s.workers[i].Hash == worker.Hash {
			s.workers[i] = worker
			replaced = true
			break
		}
	}
	if !replaced {
		s.workers = append(s.workers, worker)
	}
}

func (s *Service) SetWorkerAvailability(workerHash string, available bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	worker, ok := s.workersByHash[workerHash]
	if !ok {
		return
	}
	worker.Available = available
	s.workersByHash[workerHash] = worker
	for i := range s.workers {
		if s.workers[i].Hash == workerHash {
			s.workers[i] = worker
		}
	}
}

func (s *Service) Handler() http.Handler {
	return http.HandlerFunc(s.handle)
}

func (s *Service) handle(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromRequest(r)
	w.Header().Set("X-Request-Id", requestID)
	ctx := s.cfg.Telemetry.Extract(r.Context(), r.Header)
	ctx, span := s.cfg.Telemetry.StartSpan(ctx, "controller.request")
	defer span.End()
	traceID, spanID := telemetry.SpanIDs(ctx)
	logger := s.cfg.Logger.With(
		"request_id", requestID,
		"trace_id", traceID,
		"span_id", spanID,
		"auth_mode", s.cfg.Validator.Mode(),
	)

	if sandboxID, ok := extractSandboxID(r); ok {
		s.handleSandboxScoped(ctx, w, r, sandboxID, logger)
		return
	}

	if r.Method == http.MethodPost && r.URL.Path == "/sandboxes" {
		s.handleCreateRedirect(ctx, w, r, logger)
		return
	}

	s.writeError(w, http.StatusNotFound, "route not found")
}

func extractSandboxID(r *http.Request) (string, bool) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) >= 2 && parts[0] == "sandboxes" {
		return parts[1], true
	}
	queryID := strings.TrimSpace(r.URL.Query().Get("sandbox_id"))
	if queryID != "" {
		return queryID, true
	}
	return "", false
}

func (s *Service) handleSandboxScoped(ctx context.Context, w http.ResponseWriter, r *http.Request, sandboxID string, logger *slog.Logger) {
	parsed, err := sandboxid.Parse(sandboxID)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "malformed sandbox_id")
		return
	}

	worker, err := s.workerByHash(parsed.WorkerHash)
	if err != nil {
		if errors.Is(err, errWorkerUnknown) {
			s.writeError(w, http.StatusNotFound, "worker hash unknown")
			return
		}
		s.writeError(w, http.StatusServiceUnavailable, "worker temporarily unavailable")
		return
	}
	logger = logger.With("worker_id", worker.WorkerID, "sandbox_id", sandboxID)
	logger.Info("redirecting sandbox-scoped request to worker")

	target, err := buildRedirectURL(worker.BaseURL, r.URL)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "failed to build redirect URL")
		return
	}
	s.injectTraceHeaders(ctx, w.Header())
	http.Redirect(w, r, target, http.StatusTemporaryRedirect)
}

func (s *Service) handleCreateRedirect(ctx context.Context, w http.ResponseWriter, r *http.Request, logger *slog.Logger) {
	placementStart := s.cfg.Clock()
	ctx, span := s.cfg.Telemetry.StartSpan(ctx, "controller.placement")
	defer span.End()

	if _, err := s.cfg.Validator.Authenticate(ctx, r.Header.Get("Authorization")); err != nil {
		s.writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	var req model.CreateSandboxRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	_ = req

	worker, err := s.pickWorker()
	if err != nil {
		_ = s.cfg.Telemetry.Inc(telemetry.MetricControllerNoCapacityTotal, map[string]string{
			"status_code": "503",
			"reason":      "no_worker",
		})
		s.writeError(w, http.StatusServiceUnavailable, "no placement capacity")
		return
	}
	logger = logger.With("worker_id", worker.WorkerID)
	logger.Info("redirecting create request to worker")

	target, err := url.JoinPath(worker.BaseURL, "/sandboxes")
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "failed to build redirect URL")
		return
	}
	_ = s.cfg.Telemetry.Observe(telemetry.MetricControllerPlacementDur, s.cfg.Clock().Sub(placementStart).Seconds(), map[string]string{
		"worker_id": worker.WorkerID,
		"result":    "ok",
	})
	s.injectTraceHeaders(ctx, w.Header())
	http.Redirect(w, r, target, http.StatusTemporaryRedirect)
}

var (
	errWorkerUnknown     = errors.New("worker unknown")
	errWorkerUnavailable = errors.New("worker unavailable")
)

func (s *Service) workerByHash(hash string) (Worker, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	worker, ok := s.workersByHash[hash]
	if !ok {
		return Worker{}, errWorkerUnknown
	}
	if !worker.Available {
		return Worker{}, errWorkerUnavailable
	}
	return worker, nil
}

func (s *Service) pickWorker() (Worker, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, worker := range s.workers {
		if worker.Available {
			return worker, nil
		}
	}
	return Worker{}, errors.New("no available workers")
}

func buildRedirectURL(baseURL string, requestURL *url.URL) (string, error) {
	joined, err := url.JoinPath(baseURL, requestURL.Path)
	if err != nil {
		return "", err
	}
	if requestURL.RawQuery == "" {
		return joined, nil
	}
	return joined + "?" + requestURL.RawQuery, nil
}

func (s *Service) writeError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": message})
}

func requestIDFromRequest(r *http.Request) string {
	if requestID := strings.TrimSpace(r.Header.Get("X-Request-Id")); requestID != "" {
		return requestID
	}
	return ulid.Make().String()
}

func (s *Service) injectTraceHeaders(ctx context.Context, header http.Header) {
	carrier := make(http.Header)
	s.cfg.Telemetry.Inject(ctx, carrier)
	if traceparent := carrier.Get("Traceparent"); traceparent != "" {
		header.Set("Traceparent", traceparent)
	}
	if tracestate := carrier.Get("Tracestate"); tracestate != "" {
		header.Set("Tracestate", tracestate)
	}
}
