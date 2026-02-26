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
	"github.com/fedor/traforato/internal/httputil"
	"github.com/fedor/traforato/internal/model"
	"github.com/fedor/traforato/internal/sandboxid"
	"github.com/fedor/traforato/internal/telemetry"
	"github.com/fedor/traforato/internal/warm"
	"github.com/golang-jwt/jwt/v5"
)

type Worker struct {
	WorkerID         string
	Hostname         string
	BaseURL          string
	HardwareSKU      string
	TotalCores       int
	TotalMemoryMiB   int
	MaxLiveSandboxes int
	Available        bool
	Static           bool
	LastSeenAt       time.Time
	LeaseExpiresAt   time.Time
}

type Config struct {
	BrokerID                 string
	Validator                *auth.Validator
	Logger                   *slog.Logger
	Telemetry                *telemetry.Recorder
	Clock                    func() time.Time
	PlacementRetryMax        int
	InternalJWTSecret        string
	InternalJWTIssuer        string
	InternalJWTAudience      string
	WorkerLeaseTTL           time.Duration
	WorkerLeaseSweepInterval time.Duration
	WorkerHeartbeatHint      time.Duration
}

type Service struct {
	cfg             Config
	internalReplays *auth.ReplayCache

	mu          sync.RWMutex
	workersByID map[string]Worker
	workers     []Worker
	readyByVirt map[string]map[imageCPUKey]map[string]struct{}
	vmByHash    map[string]vmMeta
}

const (
	defaultPlacementRetryMax        = 2
	defaultWorkerLeaseTTL           = 120 * time.Second
	defaultWorkerLeaseSweepInterval = 10 * time.Second
	defaultWorkerHeartbeatHint      = 30 * time.Second
	maxInternalBodyBytes            = 1 << 20 // 1 MiB
)

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
		cfg.PlacementRetryMax = defaultPlacementRetryMax
	}
	cfg.InternalJWTSecret = strings.TrimSpace(cfg.InternalJWTSecret)
	cfg.InternalJWTIssuer = strings.TrimSpace(cfg.InternalJWTIssuer)
	cfg.InternalJWTAudience = strings.TrimSpace(cfg.InternalJWTAudience)
	if cfg.InternalJWTAudience == "" {
		cfg.InternalJWTAudience = "traforato-internal"
	}
	if cfg.WorkerLeaseTTL <= 0 {
		cfg.WorkerLeaseTTL = defaultWorkerLeaseTTL
	}
	if cfg.WorkerLeaseSweepInterval <= 0 {
		cfg.WorkerLeaseSweepInterval = defaultWorkerLeaseSweepInterval
	}
	if cfg.WorkerHeartbeatHint <= 0 {
		cfg.WorkerHeartbeatHint = defaultWorkerHeartbeatHint
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
		cfg:             cfg,
		internalReplays: auth.NewReplayCache(cfg.Clock),
		workersByID:     make(map[string]Worker),
		readyByVirt:     make(map[string]map[imageCPUKey]map[string]struct{}),
		vmByHash:        make(map[string]vmMeta),
	}
}

func (s *Service) RegisterWorker(worker Worker) {
	worker.WorkerID = strings.TrimSpace(worker.WorkerID)
	worker.Hostname = strings.TrimSpace(worker.Hostname)
	worker.BaseURL = strings.TrimSpace(worker.BaseURL)
	worker.HardwareSKU = strings.TrimSpace(worker.HardwareSKU)
	worker.Available = true
	if worker.WorkerID == "" {
		return
	}
	now := s.cfg.Clock().UTC()
	worker.Static = true
	worker.LastSeenAt = now
	worker.LeaseExpiresAt = time.Time{}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.workersByID[worker.WorkerID]; ok && existing.BaseURL != "" && existing.BaseURL != worker.BaseURL {
		s.removeWorkerReadyVMLocked(worker.WorkerID)
	}
	s.upsertWorkerLocked(worker)
}

func (s *Service) SetWorkerAvailability(workerID string, available bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	workerID = strings.TrimSpace(workerID)
	worker, ok := s.workersByID[workerID]
	if !ok {
		return
	}
	worker.Available = available
	if !available {
		s.removeWorkerReadyVMLocked(workerID)
	}
	s.upsertWorkerLocked(worker)
}

func (s *Service) RunLeaseSweeper(ctx context.Context) {
	if s.cfg.WorkerLeaseSweepInterval <= 0 {
		return
	}
	ticker := time.NewTicker(s.cfg.WorkerLeaseSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			expired := s.sweepExpiredWorkerLeases()
			if expired > 0 {
				s.cfg.Logger.Info("expired worker leases", "count", expired)
			}
		}
	}
}

func (s *Service) sweepExpiredWorkerLeases() int {
	now := s.cfg.Clock().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	expired := 0
	for workerID, worker := range s.workersByID {
		if worker.Static || !worker.Available || worker.LeaseExpiresAt.IsZero() {
			continue
		}
		if !now.After(worker.LeaseExpiresAt) {
			continue
		}
		worker.Available = false
		s.upsertWorkerLocked(worker)
		s.removeWorkerReadyVMLocked(workerID)
		expired++
	}
	return expired
}

func (s *Service) upsertWorkerLocked(worker Worker) {
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

func (s *Service) deleteWorkerLocked(workerID string) {
	delete(s.workersByID, workerID)
	for i := range s.workers {
		if s.workers[i].WorkerID == workerID {
			s.workers = append(s.workers[:i], s.workers[i+1:]...)
			break
		}
	}
}

func (s *Service) workerIsActiveAt(worker Worker, now time.Time) bool {
	if !worker.Available {
		return false
	}
	if worker.Static {
		return true
	}
	if worker.LeaseExpiresAt.IsZero() {
		return false
	}
	return !now.After(worker.LeaseExpiresAt)
}

func (s *Service) Handler() http.Handler {
	return http.HandlerFunc(s.handle)
}

func (s *Service) handle(w http.ResponseWriter, r *http.Request) {
	requestID := httputil.RequestID(r)
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

	if route, ok := extractInternalWorkerRoute(r); ok {
		switch route.Route {
		case internalWorkerRouteVMEvents:
			if r.Method == http.MethodPost {
				s.handleInternalVMEvent(ctx, w, r, route.WorkerID, logger)
				return
			}
		case internalWorkerRouteRegistration:
			if r.Method == http.MethodPut {
				s.handleInternalRegister(ctx, w, r, route.WorkerID, logger)
				return
			}
			if r.Method == http.MethodDelete {
				s.handleInternalDeregister(ctx, w, r, route.WorkerID)
				return
			}
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

const (
	internalWorkerRouteVMEvents     = "vm-events"
	internalWorkerRouteRegistration = "registration"
)

type internalWorkerRoute struct {
	WorkerID string
	Route    string
}

func extractInternalWorkerRoute(r *http.Request) (internalWorkerRoute, bool) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) == 4 && parts[0] == "internal" && parts[1] == "workers" {
		workerID := strings.TrimSpace(parts[2])
		if workerID == "" {
			return internalWorkerRoute{}, false
		}
		switch parts[3] {
		case internalWorkerRouteVMEvents, internalWorkerRouteRegistration:
			return internalWorkerRoute{
				WorkerID: workerID,
				Route:    parts[3],
			}, true
		}
	}
	return internalWorkerRoute{}, false
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
	if _, err := s.authenticateInternalWorkerJWT(ctx, r, workerID); err != nil {
		s.writeError(w, http.StatusUnauthorized, "unauthorized internal callback")
		return
	}

	var event model.WorkerVMEvent
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxInternalBodyBytes)).Decode(&event); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = s.cfg.Clock().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	worker, ok := s.workersByID[workerID]
	if !ok {
		if s.cfg.Validator.Mode() == auth.ModeProd {
			s.writeError(w, http.StatusUnauthorized, "worker must self-register")
			return
		}
		s.writeError(w, http.StatusNotFound, "worker id unknown")
		return
	}
	if s.cfg.Validator.Mode() == auth.ModeProd && !s.workerIsActiveAt(worker, s.cfg.Clock().UTC()) {
		s.writeError(w, http.StatusUnauthorized, "worker must self-register")
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

func (s *Service) handleInternalRegister(ctx context.Context, w http.ResponseWriter, r *http.Request, workerID string, logger *slog.Logger) {
	if _, err := s.authenticateInternalWorkerJWT(ctx, r, workerID); err != nil {
		s.writeError(w, http.StatusUnauthorized, "unauthorized registration")
		return
	}
	if err := sandboxid.ValidateComponentID(workerID); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid worker id")
		return
	}

	var req model.WorkerRegistrationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxInternalBodyBytes)).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	normalized, err := normalizeRegistrationRequest(req)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	now := s.cfg.Clock().UTC()
	expiresAt := now.Add(s.cfg.WorkerLeaseTTL)

	s.mu.Lock()
	if existing, ok := s.workersByID[workerID]; ok && existing.BaseURL != "" && existing.BaseURL != normalized.BaseURL {
		s.removeWorkerReadyVMLocked(workerID)
	}
	worker := Worker{
		WorkerID:         workerID,
		Hostname:         normalized.Hostname,
		BaseURL:          normalized.BaseURL,
		HardwareSKU:      normalized.HardwareSKU,
		TotalCores:       normalized.TotalCores,
		TotalMemoryMiB:   normalized.TotalMemoryMiB,
		MaxLiveSandboxes: normalized.MaxLiveSandboxes,
		Available:        true,
		Static:           false,
		LastSeenAt:       now,
		LeaseExpiresAt:   expiresAt,
	}
	s.upsertWorkerLocked(worker)
	s.mu.Unlock()

	logger.With(
		"worker_id", workerID,
		"hostname", worker.Hostname,
		"base_url", worker.BaseURL,
		"hardware_sku", worker.HardwareSKU,
		"lease_expires_at", expiresAt,
	).Info("worker registered")

	s.writeJSON(w, http.StatusOK, model.WorkerRegistrationResponse{
		WorkerID:                 workerID,
		LeaseTTLSeconds:          int(s.cfg.WorkerLeaseTTL.Seconds()),
		HeartbeatIntervalSeconds: int(s.cfg.WorkerHeartbeatHint.Seconds()),
		ExpiresAt:                expiresAt,
	})
}

func (s *Service) handleInternalDeregister(ctx context.Context, w http.ResponseWriter, r *http.Request, workerID string) {
	if _, err := s.authenticateInternalWorkerJWT(ctx, r, workerID); err != nil {
		s.writeError(w, http.StatusUnauthorized, "unauthorized deregistration")
		return
	}
	s.mu.Lock()
	worker, ok := s.workersByID[workerID]
	if ok && !worker.Static {
		s.removeWorkerReadyVMLocked(workerID)
		s.deleteWorkerLocked(workerID)
	}
	s.mu.Unlock()
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
	retry, err := httputil.ParsePlacementRetry(r.URL.Query().Get("placement_retry"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid placement_retry")
		return
	}
	_ = s.cfg.Telemetry.Observe(telemetry.MetricBrokerPlacementRetry, float64(retry), nil)
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
	if !s.workerIsActiveAt(worker, s.cfg.Clock().UTC()) {
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
	now := s.cfg.Clock().UTC()
	for _, worker := range s.workers {
		if !s.workerIsActiveAt(worker, now) {
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

func normalizeRegistrationRequest(req model.WorkerRegistrationRequest) (model.WorkerRegistrationRequest, error) {
	req.Hostname = strings.TrimSpace(req.Hostname)
	if req.Hostname == "" {
		return model.WorkerRegistrationRequest{}, errors.New("hostname is required")
	}
	baseURL, err := normalizeWorkerBaseURL(req.BaseURL)
	if err != nil {
		return model.WorkerRegistrationRequest{}, err
	}
	req.BaseURL = baseURL
	req.HardwareSKU = strings.TrimSpace(req.HardwareSKU)
	if req.TotalCores < 0 {
		return model.WorkerRegistrationRequest{}, errors.New("total_cores must be >= 0")
	}
	if req.TotalMemoryMiB < 0 {
		return model.WorkerRegistrationRequest{}, errors.New("total_memory_mib must be >= 0")
	}
	if req.MaxLiveSandboxes < 0 {
		return model.WorkerRegistrationRequest{}, errors.New("max_live_sandboxes must be >= 0")
	}
	return req, nil
}

func normalizeWorkerBaseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("base_url is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("base_url must be a valid URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("base_url must use http or https")
	}
	if parsed.Host == "" {
		return "", errors.New("base_url must include host")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("base_url must not include query or fragment")
	}
	return parsed.String(), nil
}

func (s *Service) authenticateInternalWorkerJWT(ctx context.Context, r *http.Request, workerID string) (jwt.RegisteredClaims, error) {
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
	if claims.ExpiresAt != nil && s.internalReplays.SeenOrAdd(claims.ID, claims.ExpiresAt.Time) {
		return jwt.RegisteredClaims{}, errors.New("jwt replay detected")
	}
	if claims.IssuedAt == nil || claims.IssuedAt.IsZero() {
		return jwt.RegisteredClaims{}, errors.New("missing iat")
	}
	if claims.IssuedAt.After(s.cfg.Clock().Add(5 * time.Second)) {
		return jwt.RegisteredClaims{}, errors.New("iat in future")
	}
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
	s.writeJSON(w, code, map[string]any{"error": message})
}

func (s *Service) writeJSON(w http.ResponseWriter, code int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
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
