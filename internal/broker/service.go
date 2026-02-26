package broker

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

	"github.com/fedor/traforato/internal/auth"
	"github.com/fedor/traforato/internal/model"
	"github.com/fedor/traforato/internal/sandboxid"
	"github.com/fedor/traforato/internal/telemetry"
	"github.com/oklog/ulid/v2"
)

type Worker struct {
	WorkerID    string
	Hostname    string
	BaseURL     string
	HardwareSKU string
	Available   bool
}

type Config struct {
	BrokerID  string
	Validator *auth.Validator
	Logger    *slog.Logger
	Telemetry *telemetry.Recorder
	Clock     func() time.Time
}

type Service struct {
	cfg Config

	mu          sync.RWMutex
	workersByID map[string]Worker
	workers     []Worker
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
	authModeMetric := 1.0
	if cfg.Validator.Mode() == auth.ModeDev {
		authModeMetric = 0
		cfg.Logger.Warn("auth disabled: running broker in development no-auth mode", "auth_mode", "dev")
	}
	_ = cfg.Telemetry.SetGauge(telemetry.MetricServiceAuthMode, authModeMetric, nil)
	return &Service{
		cfg:         cfg,
		workersByID: make(map[string]Worker),
	}
}

func (s *Service) RegisterWorker(worker Worker) {
	worker.WorkerID = strings.TrimSpace(worker.WorkerID)
	worker.HardwareSKU = strings.TrimSpace(worker.HardwareSKU)
	if !worker.Available {
		worker.Available = true
	}
	if worker.WorkerID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	s.workersByID[worker.WorkerID] = worker
	replaced := false
	for i := range s.workers {
		if s.workers[i].WorkerID == worker.WorkerID {
			s.workers[i] = worker
			replaced = true
			break
		}
	}
	if !replaced {
		s.workers = append(s.workers, worker)
	}
}

func (s *Service) SetWorkerAvailability(workerID string, available bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	worker, ok := s.workersByID[workerID]
	if !ok {
		return
	}
	worker.Available = available
	s.workersByID[workerID] = worker
	for i := range s.workers {
		if s.workers[i].WorkerID == workerID {
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
	ctx, span := s.cfg.Telemetry.StartSpan(ctx, "broker.request")
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
	if parsed.BrokerID != s.cfg.BrokerID {
		s.writeError(w, http.StatusNotFound, "broker id mismatch")
		return
	}

	worker, err := s.workerByID(parsed.WorkerID)
	if err != nil {
		if errors.Is(err, errWorkerUnknown) {
			s.writeError(w, http.StatusNotFound, "worker id unknown")
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
	ctx, span := s.cfg.Telemetry.StartSpan(ctx, "broker.placement")
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
	req.HardwareSKU = strings.TrimSpace(req.HardwareSKU)

	worker, err := s.pickWorker(req.HardwareSKU)
	if err != nil {
		reason := "no_worker"
		if errors.Is(err, errWorkerHardwareSKUUnavailable) {
			reason = "no_matching_hardware_sku"
		}
		_ = s.cfg.Telemetry.Inc(telemetry.MetricBrokerNoCapacityTotal, map[string]string{
			"status_code": "503",
			"reason":      reason,
		})
		s.writeError(w, http.StatusServiceUnavailable, "no placement capacity")
		return
	}
	logger = logger.With("worker_id", worker.WorkerID)
	if req.HardwareSKU != "" {
		logger = logger.With("hardware_sku", req.HardwareSKU)
	}
	logger.Info("redirecting create request to worker")

	target, err := url.JoinPath(worker.BaseURL, "/sandboxes")
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "failed to build redirect URL")
		return
	}
	_ = s.cfg.Telemetry.Observe(telemetry.MetricBrokerPlacementDur, s.cfg.Clock().Sub(placementStart).Seconds(), map[string]string{
		"worker_id": worker.WorkerID,
		"result":    "ok",
	})
	s.injectTraceHeaders(ctx, w.Header())
	http.Redirect(w, r, target, http.StatusTemporaryRedirect)
}

var (
	errWorkerUnknown                = errors.New("worker unknown")
	errWorkerUnavailable            = errors.New("worker unavailable")
	errNoAvailableWorkers           = errors.New("no available workers")
	errWorkerHardwareSKUUnavailable = errors.New("requested hardware_sku unavailable")
)

func (s *Service) workerByID(workerID string) (Worker, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	worker, ok := s.workersByID[workerID]
	if !ok {
		return Worker{}, errWorkerUnknown
	}
	if !worker.Available {
		return Worker{}, errWorkerUnavailable
	}
	return worker, nil
}

func (s *Service) pickWorker(hardwareSKU string) (Worker, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	hardwareSKU = strings.TrimSpace(hardwareSKU)
	hasAvailable := false
	for _, worker := range s.workers {
		if !worker.Available {
			continue
		}
		hasAvailable = true
		if hardwareSKU != "" && worker.HardwareSKU != hardwareSKU {
			continue
		}
		return worker, nil
	}
	if hardwareSKU != "" && hasAvailable {
		return Worker{}, errWorkerHardwareSKUUnavailable
	}
	return Worker{}, errNoAvailableWorkers
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
