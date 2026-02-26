package broker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fedor/traforato/internal/auth"
	"github.com/fedor/traforato/internal/model"
	"github.com/fedor/traforato/internal/sandboxid"
	"github.com/fedor/traforato/internal/telemetry"
	"github.com/fedor/traforato/internal/warm"
	"github.com/golang-jwt/jwt/v5"
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
	BrokerID            string
	Validator           *auth.Validator
	Logger              *slog.Logger
	Telemetry           *telemetry.Recorder
	Clock               func() time.Time
	PlacementRetryMax   int
	InternalJWTSecret   string
	InternalJWTIssuer   string
	InternalJWTAudience string
}

type Service struct {
	cfg Config

	mu          sync.RWMutex
	workersByID map[string]Worker
	workers     []Worker
	readyByVirt map[string]map[imageCPUKey]map[string]struct{}
	vmByHash    map[string]vmMeta
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
	if cfg.PlacementRetryMax < 0 {
		cfg.PlacementRetryMax = 0
	}
	if cfg.PlacementRetryMax == 0 {
		cfg.PlacementRetryMax = 2
	}
	cfg.InternalJWTSecret = strings.TrimSpace(cfg.InternalJWTSecret)
	cfg.InternalJWTIssuer = strings.TrimSpace(cfg.InternalJWTIssuer)
	cfg.InternalJWTAudience = strings.TrimSpace(cfg.InternalJWTAudience)
	if cfg.InternalJWTAudience == "" {
		cfg.InternalJWTAudience = "traforato-internal"
	}
	authModeMetric := 1.0
	if cfg.Validator.Mode() == auth.ModeDev {
		authModeMetric = 0
		cfg.Logger.Warn("auth disabled: running broker in development no-auth mode", "auth_mode", "dev")
	}
	if cfg.InternalJWTSecret == "" {
		cfg.Logger.Warn("internal worker callback auth disabled", "auth_mode", "dev", "endpoint", "/internal/workers/{worker_id}/vm-events")
	}
	_ = cfg.Telemetry.SetGauge(telemetry.MetricServiceAuthMode, authModeMetric, nil)
	return &Service{
		cfg:         cfg,
		workersByID: make(map[string]Worker),
		readyByVirt: make(map[string]map[imageCPUKey]map[string]struct{}),
		vmByHash:    make(map[string]vmMeta),
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

	if workerID, ok := extractInternalWorkerID(r); ok {
		if r.Method == http.MethodPost {
			s.handleInternalVMEvent(ctx, w, r, workerID, logger)
			return
		}
		s.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

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

func extractInternalWorkerID(r *http.Request) (string, bool) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) == 4 && parts[0] == "internal" && parts[1] == "workers" && parts[3] == "vm-events" {
		workerID := strings.TrimSpace(parts[2])
		if workerID != "" {
			return workerID, true
		}
	}
	return "", false
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

func (s *Service) handleInternalVMEvent(ctx context.Context, w http.ResponseWriter, r *http.Request, workerID string, logger *slog.Logger) {
	if _, err := s.authenticateInternalVMEvent(ctx, r, workerID); err != nil {
		s.writeError(w, http.StatusUnauthorized, "unauthorized internal callback")
		return
	}

	var event model.WorkerVMEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = s.cfg.Clock().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.workersByID[workerID]; !ok {
		s.writeError(w, http.StatusNotFound, "worker id unknown")
		return
	}
	if err := s.applyVMEventLocked(workerID, event); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid vm event")
		return
	}
	logger.With(
		"worker_id", workerID,
		"event", event.Event,
		"local_vm_id", event.LocalVMID,
	).Info("applied worker vm event")
	w.WriteHeader(http.StatusNoContent)
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
	if req.Virtualization == "" {
		req.Virtualization = "vetu"
	}
	if req.CPU <= 0 {
		req.CPU = 1
	}
	retry, err := parsePlacementRetry(r.URL.Query().Get("placement_retry"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid placement_retry")
		return
	}
	if retry > s.cfg.PlacementRetryMax {
		_ = s.cfg.Telemetry.Inc(telemetry.MetricBrokerNoCapacityTotal, map[string]string{
			"status_code": "503",
			"reason":      "placement_retry_exhausted",
		})
		s.writeError(w, http.StatusServiceUnavailable, "placement retry exhausted")
		return
	}
	req.HardwareSKU = strings.TrimSpace(req.HardwareSKU)
	tuple := warm.Tuple{
		Virtualization: req.Virtualization,
		Image:          req.Image,
		CPU:            req.CPU,
	}

	if worker, placement, ok := s.popReadyVM(tuple, req.HardwareSKU); ok {
		logger = logger.With(
			"worker_id", worker.WorkerID,
			"local_vm_id", placement.LocalVMID,
			"placement_retry", retry,
		)
		if req.HardwareSKU != "" {
			logger = logger.With("hardware_sku", req.HardwareSKU)
		}
		logger.Info("redirecting create request to worker using ready vm")
		target, err := buildCreateRedirectURL(worker.BaseURL, placement.LocalVMID, retry)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "failed to build redirect URL")
			return
		}
		_ = s.cfg.Telemetry.Observe(telemetry.MetricBrokerPlacementDur, s.cfg.Clock().Sub(placementStart).Seconds(), map[string]string{
			"worker_id": worker.WorkerID,
			"result":    "ok_ready",
		})
		s.injectTraceHeaders(ctx, w.Header())
		http.Redirect(w, r, target, http.StatusTemporaryRedirect)
		return
	}

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
	logger = logger.With("placement_retry", retry)
	if req.HardwareSKU != "" {
		logger = logger.With("hardware_sku", req.HardwareSKU)
	}
	logger.Info("redirecting create request to worker")

	target, err := buildCreateRedirectURL(worker.BaseURL, "", retry)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "failed to build redirect URL")
		return
	}
	_ = s.cfg.Telemetry.Observe(telemetry.MetricBrokerPlacementDur, s.cfg.Clock().Sub(placementStart).Seconds(), map[string]string{
		"worker_id": worker.WorkerID,
		"result":    "ok_cold",
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

func (s *Service) popReadyVM(tuple warm.Tuple, hardwareSKU string) (Worker, vmMeta, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.popReadyVMLocked(tuple, hardwareSKU)
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

func buildCreateRedirectURL(baseURL, localVMID string, retry int) (string, error) {
	joined, err := url.JoinPath(baseURL, "/sandboxes")
	if err != nil {
		return "", err
	}
	target, err := url.Parse(joined)
	if err != nil {
		return "", err
	}
	query := target.Query()
	if localVMID != "" {
		query.Set("local_vm_id", localVMID)
	}
	if retry > 0 {
		query.Set("placement_retry", strconv.Itoa(retry))
	}
	target.RawQuery = query.Encode()
	return target.String(), nil
}

func parsePlacementRetry(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	retry, err := strconv.Atoi(raw)
	if err != nil || retry < 0 {
		return 0, errors.New("invalid placement_retry")
	}
	return retry, nil
}

func (s *Service) authenticateInternalVMEvent(ctx context.Context, r *http.Request, workerID string) (jwt.RegisteredClaims, error) {
	if s.cfg.InternalJWTSecret == "" {
		return jwt.RegisteredClaims{Subject: workerID}, nil
	}
	token, err := parseBearerToken(r.Header.Get("Authorization"))
	if err != nil {
		return jwt.RegisteredClaims{}, err
	}
	claims := jwt.RegisteredClaims{}
	parserOptions := []jwt.ParserOption{
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithAudience(s.cfg.InternalJWTAudience),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(s.cfg.Clock),
	}
	if s.cfg.InternalJWTIssuer != "" {
		parserOptions = append(parserOptions, jwt.WithIssuer(s.cfg.InternalJWTIssuer))
	}
	parsed, err := jwt.ParseWithClaims(token, &claims, func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, errors.New("unsupported jwt signing algorithm")
		}
		return []byte(s.cfg.InternalJWTSecret), nil
	}, parserOptions...)
	if err != nil || !parsed.Valid {
		return jwt.RegisteredClaims{}, errors.New("invalid jwt")
	}
	if strings.TrimSpace(claims.Subject) != workerID {
		return jwt.RegisteredClaims{}, errors.New("worker_id mismatch")
	}
	if claims.ID == "" {
		return jwt.RegisteredClaims{}, errors.New("missing jti")
	}
	if claims.IssuedAt == nil || claims.IssuedAt.IsZero() {
		return jwt.RegisteredClaims{}, errors.New("missing iat")
	}
	if claims.IssuedAt.After(s.cfg.Clock().Add(5 * time.Second)) {
		return jwt.RegisteredClaims{}, errors.New("iat in future")
	}
	_ = ctx
	return claims, nil
}

func parseBearerToken(rawAuth string) (string, error) {
	rawAuth = strings.TrimSpace(rawAuth)
	if rawAuth == "" {
		return "", errors.New("missing authorization")
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(rawAuth, prefix) {
		return "", errors.New("invalid authorization")
	}
	token := strings.TrimSpace(strings.TrimPrefix(rawAuth, prefix))
	if token == "" {
		return "", errors.New("empty bearer token")
	}
	return token, nil
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
