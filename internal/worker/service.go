package worker

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fedor/traforetto/internal/auth"
	"github.com/fedor/traforetto/internal/model"
	"github.com/fedor/traforetto/internal/sandboxid"
	"github.com/fedor/traforetto/internal/telemetry"
	"github.com/fedor/traforetto/internal/warm"
	"github.com/oklog/ulid/v2"
)

type Config struct {
	WorkerID         string
	Hostname         string
	Validator        *auth.Validator
	Logger           *slog.Logger
	Telemetry        *telemetry.Recorder
	WarmPool         *warm.Manager
	TotalCores       int
	TotalMemoryMiB   int
	MaxLiveSandboxes int
	DefaultTTL       time.Duration
	Clock            func() time.Time
	Entropy          io.Reader
}

type Service struct {
	cfg Config

	mu           sync.Mutex
	sandboxes    map[string]*sandboxState
	execs        map[string]*model.Exec
	allocatedCPU int
	allocatedMiB int
}

type sandboxState struct {
	model.Sandbox
	files             map[string][]byte
	tuple             warm.Tuple
	firstExecRecorded bool
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
	if cfg.TotalCores <= 0 {
		cfg.TotalCores = runtime.NumCPU()
	}
	if cfg.TotalMemoryMiB <= 0 {
		cfg.TotalMemoryMiB = cfg.TotalCores * 1024
	}
	if cfg.MaxLiveSandboxes <= 0 {
		if runtime.GOOS == "darwin" {
			cfg.MaxLiveSandboxes = 2
		} else {
			cfg.MaxLiveSandboxes = cfg.TotalCores
		}
	}
	if cfg.DefaultTTL <= 0 {
		cfg.DefaultTTL = 30 * time.Minute
	}
	if cfg.Entropy == nil {
		cfg.Entropy = rand.Reader
	}
	if cfg.Telemetry == nil {
		cfg.Telemetry = telemetry.NewRecorder(cfg.Validator.Mode())
	}
	if cfg.WarmPool == nil {
		cfg.WarmPool = warm.NewManager(cfg.Clock, nil)
	}

	authMode := "prod"
	authModeMetric := 1.0
	if cfg.Validator.Mode() == auth.ModeDev {
		authMode = "dev"
		authModeMetric = 0
		cfg.Logger.Warn("auth disabled: running worker in development no-auth mode", "auth_mode", authMode)
	}
	_ = cfg.Telemetry.SetGauge(telemetry.MetricServiceAuthMode, authModeMetric, nil)
	_ = cfg.Telemetry.SetGauge(telemetry.MetricWorkerCPUTotal, float64(cfg.TotalCores), map[string]string{
		"worker_id": cfg.WorkerID,
	})
	_ = cfg.Telemetry.SetGauge(telemetry.MetricWorkerMemoryTotal, float64(cfg.TotalMemoryMiB), map[string]string{
		"worker_id": cfg.WorkerID,
	})
	cfg.WarmPool.OnWorkerRegister(cfg.MaxLiveSandboxes)

	return &Service{
		cfg:       cfg,
		sandboxes: make(map[string]*sandboxState),
		execs:     make(map[string]*model.Exec),
	}
}

func (s *Service) Handler() http.Handler {
	return http.HandlerFunc(s.handle)
}

func (s *Service) HandleSSHDrop(tuple warm.Tuple) error {
	_ = s.cfg.Telemetry.Inc(telemetry.MetricWorkerSSHReconnectsTotal, map[string]string{
		"worker_id": s.cfg.WorkerID,
		"cpu":       strconv.Itoa(tuple.CPU),
	})
	if err := s.cfg.WarmPool.HandleSSHDrop(tuple); err != nil {
		_ = s.cfg.Telemetry.Inc(telemetry.MetricWorkerWarmupFailuresTotal, map[string]string{
			"worker_id": s.cfg.WorkerID,
			"cpu":       strconv.Itoa(tuple.CPU),
			"reason":    "rewarm",
		})
		return err
	}
	_ = s.cfg.Telemetry.SetGauge(telemetry.MetricWorkerWarmReady, float64(s.cfg.WarmPool.ReadyCount(tuple)), map[string]string{
		"worker_id": s.cfg.WorkerID,
		"cpu":       strconv.Itoa(tuple.CPU),
	})
	_ = s.cfg.Telemetry.SetGauge(telemetry.MetricWorkerWarmDeficit, float64(s.cfg.WarmPool.WarmDeficit(tuple)), map[string]string{
		"worker_id": s.cfg.WorkerID,
		"cpu":       strconv.Itoa(tuple.CPU),
	})
	return nil
}

func (s *Service) handle(w http.ResponseWriter, r *http.Request) {
	requestID := requestIDFromRequest(r)
	w.Header().Set("X-Request-Id", requestID)

	ctx := s.cfg.Telemetry.Extract(r.Context(), r.Header)
	ctx, span := s.cfg.Telemetry.StartSpan(ctx, "worker.request")
	defer span.End()
	traceID, spanID := telemetry.SpanIDs(ctx)
	logger := s.cfg.Logger.With(
		"request_id", requestID,
		"trace_id", traceID,
		"span_id", spanID,
		"worker_id", s.cfg.WorkerID,
		"auth_mode", s.cfg.Validator.Mode(),
	)

	principal, err := s.cfg.Validator.Authenticate(ctx, r.Header.Get("Authorization"))
	if err != nil {
		_ = s.cfg.Telemetry.Inc(telemetry.MetricWorkerAuthFailuresTotal, map[string]string{
			"worker_id":   s.cfg.WorkerID,
			"status_code": strconv.Itoa(http.StatusUnauthorized),
			"reason":      "jwt",
		})
		logger.Warn("authentication failed")
		s.writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	parts := splitPath(r.URL.Path)
	if len(parts) == 0 {
		s.writeError(w, http.StatusNotFound, "route not found")
		return
	}

	if len(parts) == 1 && parts[0] == "sandboxes" && r.Method == http.MethodPost {
		s.handleCreateSandbox(ctx, w, r, principal)
		return
	}

	if len(parts) < 2 || parts[0] != "sandboxes" {
		s.writeError(w, http.StatusNotFound, "route not found")
		return
	}

	sandboxID := parts[1]
	if _, err := sandboxid.Parse(sandboxID); err != nil {
		logger.Warn("malformed sandbox id", "sandbox_id", sandboxID)
		s.writeError(w, http.StatusBadRequest, "malformed sandbox_id")
		return
	}

	if len(parts) == 2 && r.Method == http.MethodGet {
		s.handleGetSandbox(w, principal, sandboxID)
		return
	}
	if len(parts) == 2 && r.Method == http.MethodDelete {
		s.handleDeleteSandbox(w, principal, sandboxID)
		return
	}
	if len(parts) == 3 && parts[2] == "lease" && r.Method == http.MethodPatch {
		s.handlePatchLease(w, r, principal, sandboxID)
		return
	}
	if len(parts) == 3 && parts[2] == "files" && r.Method == http.MethodPut {
		s.handlePutFiles(w, r, principal, sandboxID)
		return
	}
	if len(parts) == 3 && parts[2] == "exec" && r.Method == http.MethodPost {
		s.handleCreateExec(w, r, principal, sandboxID)
		return
	}
	if len(parts) == 4 && parts[2] == "exec" && parts[3] == "ws" && r.Method == http.MethodGet {
		s.writeError(w, http.StatusNotImplemented, "websocket exec is optional and not enabled")
		return
	}
	if len(parts) == 4 && parts[2] == "exec" && r.Method == http.MethodGet {
		s.handleGetExec(w, principal, sandboxID, parts[3])
		return
	}
	if len(parts) == 5 && parts[2] == "exec" && parts[4] == "frames" && r.Method == http.MethodGet {
		s.handleGetFrames(w, r, principal, sandboxID, parts[3])
		return
	}
	s.writeError(w, http.StatusNotFound, "route not found")
}

func splitPath(path string) []string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

func (s *Service) handleCreateSandbox(ctx context.Context, w http.ResponseWriter, r *http.Request, principal auth.Principal) {
	started := s.cfg.Clock()
	ctx, span := s.cfg.Telemetry.StartSpan(ctx, "worker.sandbox.create")
	defer span.End()

	var req model.CreateSandboxRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Image == "" {
		s.writeError(w, http.StatusBadRequest, "image is required")
		return
	}
	if req.CPU <= 0 {
		req.CPU = 1
	}
	if req.Virtualization == "" {
		req.Virtualization = "vetu"
	}
	tuple := warm.Tuple{
		Virtualization: req.Virtualization,
		Image:          req.Image,
		CPU:            req.CPU,
	}
	ttl := s.cfg.DefaultTTL
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}

	workerHash := sandboxid.WorkerHash(s.cfg.Hostname)
	if workerHash == "" {
		s.writeError(w, http.StatusInternalServerError, "worker hostname is required")
		return
	}
	mibPerCPU := s.cfg.TotalMemoryMiB / s.cfg.TotalCores
	if mibPerCPU <= 0 {
		mibPerCPU = 512
	}
	memoryMiB := req.CPU * mibPerCPU

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sandboxes) >= s.cfg.MaxLiveSandboxes {
		s.writeError(w, http.StatusServiceUnavailable, "no capacity: max sandbox count reached")
		return
	}
	if s.allocatedCPU+req.CPU > s.cfg.TotalCores {
		s.writeError(w, http.StatusServiceUnavailable, "no capacity: cpu limit reached")
		return
	}
	if s.allocatedMiB+memoryMiB > s.cfg.TotalMemoryMiB {
		s.writeError(w, http.StatusServiceUnavailable, "no capacity: memory limit reached")
		return
	}

	sandboxID, err := sandboxid.New(s.cfg.Hostname, s.cfg.Entropy)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "failed to allocate sandbox id")
		return
	}

	now := s.cfg.Clock().UTC()
	sbx := model.Sandbox{
		SandboxID:      sandboxID,
		OwnerClientID:  principal.ClientID,
		Image:          req.Image,
		CPU:            req.CPU,
		MemoryMiB:      memoryMiB,
		Virtualization: req.Virtualization,
		CreatedAt:      now,
		ExpiresAt:      now.Add(ttl),
	}
	startType := "cold"
	if s.cfg.WarmPool.ConsumeReady(tuple) {
		startType = "warm"
		_ = s.cfg.Telemetry.Inc(telemetry.MetricWorkerWarmHitTotal, map[string]string{
			"worker_id": s.cfg.WorkerID,
			"cpu":       strconv.Itoa(req.CPU),
		})
	} else {
		_ = s.cfg.Telemetry.Inc(telemetry.MetricWorkerWarmMissTotal, map[string]string{
			"worker_id": s.cfg.WorkerID,
			"cpu":       strconv.Itoa(req.CPU),
		})
	}
	s.cfg.WarmPool.RecordDemand(tuple)

	s.sandboxes[sandboxID] = &sandboxState{
		Sandbox: sbx,
		files:   make(map[string][]byte),
		tuple:   tuple,
	}
	s.allocatedCPU += req.CPU
	s.allocatedMiB += memoryMiB
	_ = s.cfg.Telemetry.SetGauge(telemetry.MetricWorkerCPUAllocated, float64(s.allocatedCPU), map[string]string{
		"worker_id": s.cfg.WorkerID,
	})
	_ = s.cfg.Telemetry.SetGauge(telemetry.MetricWorkerMemoryAllocated, float64(s.allocatedMiB), map[string]string{
		"worker_id": s.cfg.WorkerID,
	})
	_ = s.cfg.Telemetry.SetGauge(telemetry.MetricWorkerSandboxesLive, float64(len(s.sandboxes)), map[string]string{
		"worker_id": s.cfg.WorkerID,
	})
	_ = s.cfg.Telemetry.Observe(telemetry.MetricWorkerReadyDuration, s.cfg.Clock().Sub(started).Seconds(), map[string]string{
		"worker_id":  s.cfg.WorkerID,
		"start_type": startType,
		"cpu":        strconv.Itoa(req.CPU),
	})
	_ = ctx

	s.writeJSON(w, http.StatusCreated, map[string]any{
		"sandbox_id":     sbx.SandboxID,
		"expires_at":     sbx.ExpiresAt,
		"cpu":            sbx.CPU,
		"memory_mib":     sbx.MemoryMiB,
		"virtualization": sbx.Virtualization,
		"worker_hash":    workerHash,
	})
}

func (s *Service) handleGetSandbox(w http.ResponseWriter, principal auth.Principal, sandboxID string) {
	sbx, err := s.getOwnedSandbox(principal, sandboxID)
	if err != nil {
		s.writeOwnedError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, sbx.Sandbox)
}

func (s *Service) handleDeleteSandbox(w http.ResponseWriter, principal auth.Principal, sandboxID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sbx, ok := s.sandboxes[sandboxID]
	if !ok {
		s.writeError(w, http.StatusNotFound, "sandbox not found")
		return
	}
	if err := s.ensureOwnership(principal, sbx.OwnerClientID); err != nil {
		s.writeOwnedError(w, err)
		return
	}
	delete(s.sandboxes, sandboxID)
	s.allocatedCPU -= sbx.CPU
	s.allocatedMiB -= sbx.MemoryMiB

	for execID, exec := range s.execs {
		if exec.SandboxID == sandboxID {
			delete(s.execs, execID)
		}
	}
	targets := s.cfg.WarmPool.OnSandboxDelete(s.cfg.MaxLiveSandboxes)
	target := targets[sbx.tuple]
	ready := s.cfg.WarmPool.ReadyCount(sbx.tuple)
	_ = s.cfg.Telemetry.SetGauge(telemetry.MetricWorkerCPUAllocated, float64(s.allocatedCPU), map[string]string{
		"worker_id": s.cfg.WorkerID,
	})
	_ = s.cfg.Telemetry.SetGauge(telemetry.MetricWorkerMemoryAllocated, float64(s.allocatedMiB), map[string]string{
		"worker_id": s.cfg.WorkerID,
	})
	_ = s.cfg.Telemetry.SetGauge(telemetry.MetricWorkerSandboxesLive, float64(len(s.sandboxes)), map[string]string{
		"worker_id": s.cfg.WorkerID,
	})
	_ = s.cfg.Telemetry.SetGauge(telemetry.MetricWorkerWarmTarget, float64(target), map[string]string{
		"worker_id": s.cfg.WorkerID,
		"cpu":       strconv.Itoa(sbx.CPU),
	})
	_ = s.cfg.Telemetry.SetGauge(telemetry.MetricWorkerWarmReady, float64(ready), map[string]string{
		"worker_id": s.cfg.WorkerID,
		"cpu":       strconv.Itoa(sbx.CPU),
	})
	_ = s.cfg.Telemetry.SetGauge(telemetry.MetricWorkerWarmDeficit, float64(maxInt(target-ready, 0)), map[string]string{
		"worker_id": s.cfg.WorkerID,
		"cpu":       strconv.Itoa(sbx.CPU),
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) handlePatchLease(w http.ResponseWriter, r *http.Request, principal auth.Principal, sandboxID string) {
	ttlSeconds, _ := strconv.Atoi(r.URL.Query().Get("ttl_seconds"))
	if ttlSeconds <= 0 {
		s.writeError(w, http.StatusBadRequest, "ttl_seconds must be > 0")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	sbx, ok := s.sandboxes[sandboxID]
	if !ok {
		s.writeError(w, http.StatusNotFound, "sandbox not found")
		return
	}
	if err := s.ensureOwnership(principal, sbx.OwnerClientID); err != nil {
		s.writeOwnedError(w, err)
		return
	}
	sbx.ExpiresAt = s.cfg.Clock().UTC().Add(time.Duration(ttlSeconds) * time.Second)
	s.writeJSON(w, http.StatusOK, map[string]any{
		"sandbox_id": sbx.SandboxID,
		"expires_at": sbx.ExpiresAt,
	})
}

func (s *Service) handlePutFiles(w http.ResponseWriter, r *http.Request, principal auth.Principal, sandboxID string) {
	path := r.URL.Query().Get("path")
	if path == "" {
		s.writeError(w, http.StatusBadRequest, "path query parameter is required")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "failed to read body")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	sbx, ok := s.sandboxes[sandboxID]
	if !ok {
		s.writeError(w, http.StatusNotFound, "sandbox not found")
		return
	}
	if err := s.ensureOwnership(principal, sbx.OwnerClientID); err != nil {
		s.writeOwnedError(w, err)
		return
	}
	sbx.files[path] = body
	s.writeJSON(w, http.StatusOK, map[string]any{
		"sandbox_id": sandboxID,
		"path":       path,
		"bytes":      len(body),
	})
}

func (s *Service) handleCreateExec(w http.ResponseWriter, r *http.Request, principal auth.Principal, sandboxID string) {
	started := s.cfg.Clock()
	sbx, err := s.getOwnedSandbox(principal, sandboxID)
	if err != nil {
		s.writeOwnedError(w, err)
		return
	}

	var req struct {
		Command string `json:"command"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Command == "" {
		req.Command = "true"
	}

	execID, err := newExecID()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "failed to allocate exec id")
		return
	}
	now := s.cfg.Clock().UTC()
	exitCode := 0
	completed := now.Add(10 * time.Millisecond)
	s.mu.Lock()
	if !sbx.firstExecRecorded {
		sbx.firstExecRecorded = true
		_ = s.cfg.Telemetry.Observe(telemetry.MetricWorkerFirstExecTTI, now.Sub(sbx.CreatedAt).Seconds(), map[string]string{
			"worker_id": s.cfg.WorkerID,
			"cpu":       strconv.Itoa(sbx.CPU),
		})
	}
	s.mu.Unlock()
	exec := &model.Exec{
		ExecID:    execID,
		SandboxID: sbx.SandboxID,
		Status:    "exited",
		ExitCode:  &exitCode,
		Command:   req.Command,
		StartedAt: now,
		Completed: &completed,
		Frames: []model.Frame{
			{Type: "stdout", Data: fmt.Sprintf("executed: %s\n", req.Command), Timestamp: now},
			{Type: "exit", Data: "0", Timestamp: completed},
		},
	}
	s.mu.Lock()
	s.execs[execID] = exec
	s.mu.Unlock()
	_ = s.cfg.Telemetry.Observe(telemetry.MetricWorkerExecStartDuration, s.cfg.Clock().Sub(started).Seconds(), map[string]string{
		"worker_id": s.cfg.WorkerID,
		"cpu":       strconv.Itoa(sbx.CPU),
	})
	_ = s.cfg.Telemetry.Observe(telemetry.MetricWorkerExecDuration, completed.Sub(now).Seconds(), map[string]string{
		"worker_id": s.cfg.WorkerID,
		"cpu":       strconv.Itoa(sbx.CPU),
	})

	s.writeJSON(w, http.StatusAccepted, map[string]any{
		"exec_id": execID,
	})
}

func (s *Service) handleGetExec(w http.ResponseWriter, principal auth.Principal, sandboxID, execID string) {
	sbx, err := s.getOwnedSandbox(principal, sandboxID)
	if err != nil {
		s.writeOwnedError(w, err)
		return
	}
	_ = sbx
	s.mu.Lock()
	defer s.mu.Unlock()

	exec, ok := s.execs[execID]
	if !ok || exec.SandboxID != sandboxID {
		s.writeError(w, http.StatusNotFound, "exec not found")
		return
	}
	s.writeJSON(w, http.StatusOK, exec)
}

func (s *Service) handleGetFrames(w http.ResponseWriter, r *http.Request, principal auth.Principal, sandboxID, execID string) {
	if _, err := s.getOwnedSandbox(principal, sandboxID); err != nil {
		s.writeOwnedError(w, err)
		return
	}
	cursor, _ := strconv.Atoi(r.URL.Query().Get("cursor"))
	if cursor < 0 {
		cursor = 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	exec, ok := s.execs[execID]
	if !ok || exec.SandboxID != sandboxID {
		s.writeError(w, http.StatusNotFound, "exec not found")
		return
	}
	if cursor > len(exec.Frames) {
		cursor = len(exec.Frames)
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"frames":       exec.Frames[cursor:],
		"next_cursor":  len(exec.Frames),
		"has_more":     false,
		"wait_applied": r.URL.Query().Get("wait") != "",
	})
}

func (s *Service) getOwnedSandbox(principal auth.Principal, sandboxID string) (*sandboxState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sbx, ok := s.sandboxes[sandboxID]
	if !ok {
		return nil, errors.New("sandbox not found")
	}
	if err := s.ensureOwnership(principal, sbx.OwnerClientID); err != nil {
		return nil, err
	}
	return sbx, nil
}

func (s *Service) ensureOwnership(principal auth.Principal, ownerClientID string) error {
	if s.cfg.Validator.Mode() == auth.ModeDev {
		return nil
	}
	if principal.ClientID != ownerClientID {
		return fmt.Errorf("sandbox ownership mismatch")
	}
	return nil
}

func newExecID() (string, error) {
	id, err := ulid.Make().MarshalText()
	if err != nil {
		return "", err
	}
	return "exec_" + string(id), nil
}

func (s *Service) writeOwnedError(w http.ResponseWriter, err error) {
	switch {
	case err == nil:
		return
	case strings.Contains(err.Error(), "not found"):
		s.writeError(w, http.StatusNotFound, err.Error())
	case strings.Contains(err.Error(), "ownership"):
		s.writeError(w, http.StatusForbidden, err.Error())
	default:
		s.writeError(w, http.StatusUnauthorized, err.Error())
	}
}

func (s *Service) writeError(w http.ResponseWriter, code int, message string) {
	s.writeJSON(w, code, map[string]any{"error": message})
}

func (s *Service) writeJSON(w http.ResponseWriter, code int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
}

func requestIDFromRequest(r *http.Request) string {
	if requestID := strings.TrimSpace(r.Header.Get("X-Request-Id")); requestID != "" {
		return requestID
	}
	return ulid.Make().String()
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
