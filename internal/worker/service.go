package worker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"runtime"
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

type Config struct {
	WorkerID         string
	BrokerID         string
	BrokerControlURL string
	Hostname         string
	AdvertiseURL     string
	HardwareSKU      string
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
	HTTPClient       *http.Client

	RegistrationHeartbeat     time.Duration
	RegistrationJitterPercent int

	InternalJWTSecret   string
	InternalJWTIssuer   string
	InternalJWTAudience string
}

type Service struct {
	cfg            Config
	proxyTransport http.RoundTripper

	mu           sync.Mutex
	sandboxes    map[string]*sandboxState
	execs        map[string]*model.Exec
	allocatedCPU int
	allocatedMiB int
	vms          map[string]*vmRecord
}

type sandboxState struct {
	model.Sandbox
	files             map[string][]byte
	dirs              map[string]struct{}
	fileModTimes      map[string]time.Time
	dirModTimes       map[string]time.Time
	tuple             warm.Tuple
	firstExecRecorded bool
}

type vmState string

const (
	vmStateReady   vmState = "READY"
	vmStateClaimed vmState = "CLAIMED"
	vmStateRetired vmState = "RETIRED"
)

type vmRecord struct {
	mu    sync.Mutex
	state vmState
	tuple warm.Tuple
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
	cfg.BrokerControlURL = strings.TrimSpace(cfg.BrokerControlURL)
	cfg.AdvertiseURL = strings.TrimSpace(cfg.AdvertiseURL)
	cfg.InternalJWTSecret = strings.TrimSpace(cfg.InternalJWTSecret)
	cfg.InternalJWTIssuer = strings.TrimSpace(cfg.InternalJWTIssuer)
	cfg.InternalJWTAudience = strings.TrimSpace(cfg.InternalJWTAudience)
	if cfg.InternalJWTAudience == "" {
		cfg.InternalJWTAudience = "traforato-internal"
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 3 * time.Second}
	}
	if cfg.RegistrationHeartbeat <= 0 {
		cfg.RegistrationHeartbeat = 30 * time.Second
	}
	if cfg.RegistrationJitterPercent < 0 {
		cfg.RegistrationJitterPercent = 0
	}
	if cfg.RegistrationJitterPercent > 95 {
		cfg.RegistrationJitterPercent = 95
	}

	authModeMetric := 1.0
	if cfg.Validator.Mode() == auth.ModeDev {
		authModeMetric = 0
		cfg.Logger.Warn("auth disabled: running worker in development no-auth mode", "auth_mode", "dev")
	}
	_ = cfg.Telemetry.SetGauge(telemetry.MetricServiceAuthMode, authModeMetric, nil)
	_ = cfg.Telemetry.SetGauge(telemetry.MetricWorkerCPUTotal, float64(cfg.TotalCores), map[string]string{
		"worker_id": cfg.WorkerID,
	})
	_ = cfg.Telemetry.SetGauge(telemetry.MetricWorkerMemoryTotal, float64(cfg.TotalMemoryMiB), map[string]string{
		"worker_id": cfg.WorkerID,
	})
	cfg.WarmPool.OnWorkerRegister(cfg.MaxLiveSandboxes)

	proxyTransport := http.DefaultTransport.(*http.Transport).Clone()
	proxyTransport.ResponseHeaderTimeout = 30 * time.Second

	svc := &Service{
		cfg:            cfg,
		proxyTransport: proxyTransport,
		sandboxes:      make(map[string]*sandboxState),
		execs:          make(map[string]*model.Exec),
		vms:            make(map[string]*vmRecord),
	}
	svc.bootstrapReadyVMs()
	return svc
}

func (s *Service) Handler() http.Handler {
	return http.HandlerFunc(s.handle)
}

func (s *Service) HandleSSHDrop(tuple warm.Tuple) error {
	tuple = normalizeTuple(tuple)
	retired := s.retireReadyVMsForTuple(tuple)
	for _, localVMID := range retired {
		s.emitVMEvent(context.Background(), model.WorkerVMEvent{
			Event:          model.WorkerVMEventRetired,
			LocalVMID:      localVMID,
			Virtualization: tuple.Virtualization,
			Image:          tuple.Image,
			CPU:            tuple.CPU,
			Timestamp:      s.cfg.Clock().UTC(),
		})
	}
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
	s.ensureReadyVMCount(tuple, s.cfg.WarmPool.ReadyCount(tuple))
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
	if len(parts) == 3 && parts[2] == "files" && r.Method == http.MethodGet {
		s.handleGetFile(w, r, principal, sandboxID)
		return
	}
	if len(parts) == 3 && parts[2] == "files" && r.Method == http.MethodDelete {
		s.handleDeleteFiles(w, r, principal, sandboxID)
		return
	}
	if len(parts) == 4 && parts[2] == "files" && parts[3] == "stat" && r.Method == http.MethodGet {
		s.handleGetFileStat(w, r, principal, sandboxID)
		return
	}
	if len(parts) == 4 && parts[2] == "files" && parts[3] == "list" && r.Method == http.MethodGet {
		s.handleListFiles(w, r, principal, sandboxID)
		return
	}
	if len(parts) == 4 && parts[2] == "files" && parts[3] == "mkdir" && r.Method == http.MethodPost {
		s.handleMkdirFiles(w, r, principal, sandboxID)
		return
	}
	if len(parts) == 3 && parts[2] == "exec" && r.Method == http.MethodPost {
		s.handleCreateExec(w, r, principal, sandboxID)
		return
	}
	if len(parts) == 4 && parts[2] == "exec" && parts[3] == "code" && r.Method == http.MethodPost {
		s.handleRunCode(w, r, principal, sandboxID)
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
	if len(parts) >= 4 && parts[2] == "proxy" {
		s.handleProxy(w, r, principal, sandboxID, parts)
		return
	}
	if len(parts) == 5 && parts[2] == "ports" && parts[4] == "url" && r.Method == http.MethodGet {
		s.handleGetPortURL(w, r, principal, sandboxID, parts[3])
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
	retry, err := parsePlacementRetry(r.URL.Query().Get("placement_retry"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid placement_retry")
		return
	}
	hintedLocalVMID := strings.TrimSpace(r.URL.Query().Get("local_vm_id"))
	if hintedLocalVMID != "" {
		if err := sandboxid.ValidateLocalVMID(hintedLocalVMID); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid local_vm_id")
			return
		}
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

	if s.cfg.BrokerID == "" || s.cfg.WorkerID == "" {
		s.writeError(w, http.StatusInternalServerError, "broker_id and worker_id are required")
		return
	}
	mibPerCPU := s.cfg.TotalMemoryMiB / s.cfg.TotalCores
	if mibPerCPU <= 0 {
		mibPerCPU = 512
	}
	memoryMiB := req.CPU * mibPerCPU

	s.mu.Lock()
	if len(s.sandboxes) >= s.cfg.MaxLiveSandboxes {
		s.mu.Unlock()
		s.writeError(w, http.StatusServiceUnavailable, "no capacity: max sandbox count reached")
		return
	}
	if s.allocatedCPU+req.CPU > s.cfg.TotalCores {
		s.mu.Unlock()
		s.writeError(w, http.StatusServiceUnavailable, "no capacity: cpu limit reached")
		return
	}
	if s.allocatedMiB+memoryMiB > s.cfg.TotalMemoryMiB {
		s.mu.Unlock()
		s.writeError(w, http.StatusServiceUnavailable, "no capacity: memory limit reached")
		return
	}

	now := s.cfg.Clock().UTC()
	startType := "cold"
	claimedHintedVM := false
	if hintedLocalVMID != "" {
		if !s.claimReadyVMLocked(hintedLocalVMID, tuple) {
			s.mu.Unlock()
			if err := s.redirectBackToBroker(w, r, retry+1); err != nil {
				s.writeError(w, http.StatusServiceUnavailable, "unable to retry placement")
			}
			return
		}
		claimedHintedVM = true
		startType = "warm"
		if s.cfg.WarmPool.ConsumeReady(tuple) {
			// Keep warm counters aligned with concrete VM claims where possible.
		}
		_ = s.cfg.Telemetry.Inc(telemetry.MetricWorkerWarmHitTotal, map[string]string{
			"worker_id": s.cfg.WorkerID,
			"cpu":       strconv.Itoa(req.CPU),
		})
	} else {
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
	}

	sandboxID, err := s.newSandboxID(hintedLocalVMID)
	if err != nil {
		s.mu.Unlock()
		s.writeError(w, http.StatusInternalServerError, "failed to allocate sandbox id")
		return
	}

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
	s.cfg.WarmPool.RecordDemand(tuple)

	s.sandboxes[sandboxID] = &sandboxState{
		Sandbox: sbx,
		files:   make(map[string][]byte),
		dirs: map[string]struct{}{
			"/":          {},
			"/workspace": {},
		},
		fileModTimes: make(map[string]time.Time),
		dirModTimes: map[string]time.Time{
			"/":          now,
			"/workspace": now,
		},
		tuple: tuple,
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
	s.mu.Unlock()

	if claimedHintedVM {
		s.emitVMEvent(ctx, model.WorkerVMEvent{
			Event:          model.WorkerVMEventClaimed,
			LocalVMID:      hintedLocalVMID,
			Virtualization: tuple.Virtualization,
			Image:          tuple.Image,
			CPU:            tuple.CPU,
			Timestamp:      now,
		})
	}
	s.writeJSON(w, http.StatusCreated, map[string]any{
		"sandbox_id":     sbx.SandboxID,
		"expires_at":     sbx.ExpiresAt,
		"cpu":            sbx.CPU,
		"memory_mib":     sbx.MemoryMiB,
		"virtualization": sbx.Virtualization,
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
	_ = s.cfg.Telemetry.SetGauge(telemetry.MetricWorkerWarmDeficit, float64(max(target-ready, 0)), map[string]string{
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
	s.handleWriteFile(w, r, principal, sandboxID)
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

func (s *Service) bootstrapReadyVMs() {
	readyByTuple := s.cfg.WarmPool.ReadySnapshot()
	for tuple, count := range readyByTuple {
		s.ensureReadyVMCount(tuple, count)
	}
}

func (s *Service) ensureReadyVMCount(tuple warm.Tuple, target int) {
	tuple = normalizeTuple(tuple)
	if target <= 0 {
		return
	}
	existing := 0
	s.mu.Lock()
	for _, record := range s.vms {
		record.mu.Lock()
		ready := record.state == vmStateReady && record.tuple == tuple
		record.mu.Unlock()
		if ready {
			existing++
		}
	}
	s.mu.Unlock()
	for i := existing; i < target; i++ {
		localVMID, err := sandboxid.NewLocalVMID(s.cfg.Entropy)
		if err != nil {
			s.cfg.Logger.Warn("failed to allocate local vm id for ready pool", "error", err)
			break
		}
		s.mu.Lock()
		s.vms[localVMID] = &vmRecord{
			state: vmStateReady,
			tuple: tuple,
		}
		s.mu.Unlock()
		s.emitVMEvent(context.Background(), model.WorkerVMEvent{
			Event:          model.WorkerVMEventReady,
			LocalVMID:      localVMID,
			Virtualization: tuple.Virtualization,
			Image:          tuple.Image,
			CPU:            tuple.CPU,
			Timestamp:      s.cfg.Clock().UTC(),
		})
	}
}

func (s *Service) retireReadyVMsForTuple(tuple warm.Tuple) []string {
	tuple = normalizeTuple(tuple)
	retired := make([]string, 0)
	s.mu.Lock()
	defer s.mu.Unlock()
	for localVMID, record := range s.vms {
		record.mu.Lock()
		ready := record.state == vmStateReady && record.tuple == tuple
		if ready {
			record.state = vmStateRetired
			delete(s.vms, localVMID)
			retired = append(retired, localVMID)
		}
		record.mu.Unlock()
	}
	return retired
}

func (s *Service) claimReadyVMLocked(localVMID string, tuple warm.Tuple) bool {
	record, ok := s.vms[localVMID]
	if !ok {
		return false
	}
	tuple = normalizeTuple(tuple)
	record.mu.Lock()
	defer record.mu.Unlock()
	if record.state != vmStateReady || record.tuple != tuple {
		return false
	}
	record.state = vmStateClaimed
	delete(s.vms, localVMID)
	return true
}

func (s *Service) newSandboxID(localVMID string) (string, error) {
	if localVMID != "" {
		return sandboxid.NewFromLocalVMID(s.cfg.BrokerID, s.cfg.WorkerID, localVMID)
	}
	return sandboxid.New(s.cfg.BrokerID, s.cfg.WorkerID, s.cfg.Entropy)
}

func (s *Service) redirectBackToBroker(w http.ResponseWriter, r *http.Request, retry int) error {
	baseURL := strings.TrimSpace(s.cfg.BrokerControlURL)
	if baseURL == "" {
		return errors.New("broker control url is required for placement retry")
	}
	target, err := url.JoinPath(baseURL, "/sandboxes")
	if err != nil {
		return err
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return err
	}
	query := parsed.Query()
	if retry > 0 {
		query.Set("placement_retry", strconv.Itoa(retry))
	}
	parsed.RawQuery = query.Encode()
	http.Redirect(w, r, parsed.String(), http.StatusTemporaryRedirect)
	return nil
}

func (s *Service) RunRegistrationLoop(ctx context.Context) {
	if strings.TrimSpace(s.cfg.BrokerControlURL) == "" {
		return
	}

	backoff := time.Second
	registered := false
	for {
		err := s.registerWithBroker(ctx)
		if err == nil {
			if !registered {
				s.emitReadyVMSnapshot()
			}
			registered = true
			backoff = time.Second
			wait := s.registrationDelayWithJitter(s.cfg.RegistrationHeartbeat)
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			continue
		}

		registered = false
		s.cfg.Logger.Warn("worker registration failed", "worker_id", s.cfg.WorkerID, "error", err, "retry_in", backoff.String())
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
	}
}

func (s *Service) DeregisterWorker(ctx context.Context) {
	if strings.TrimSpace(s.cfg.BrokerControlURL) == "" {
		return
	}
	if err := s.deregisterFromBroker(ctx); err != nil {
		s.cfg.Logger.Warn("worker deregistration failed", "worker_id", s.cfg.WorkerID, "error", err)
	}
}

func (s *Service) registrationDelayWithJitter(base time.Duration) time.Duration {
	if base <= 0 {
		base = 30 * time.Second
	}
	jitterPercent := s.cfg.RegistrationJitterPercent
	if jitterPercent <= 0 {
		return base
	}
	rangePercent := jitterPercent * 2
	n, err := rand.Int(s.cfg.Entropy, big.NewInt(int64(rangePercent+1)))
	if err != nil {
		return base
	}
	offsetPercent := int(n.Int64()) - jitterPercent
	factor := 1 + float64(offsetPercent)/100.0
	delay := time.Duration(float64(base) * factor)
	if delay < time.Second {
		return time.Second
	}
	return delay
}

func (s *Service) registerWithBroker(ctx context.Context) error {
	target, err := url.JoinPath(strings.TrimSpace(s.cfg.BrokerControlURL), "/internal/workers", s.cfg.WorkerID, "registration")
	if err != nil {
		return err
	}
	payload := model.WorkerRegistrationRequest{
		Hostname:         strings.TrimSpace(s.cfg.Hostname),
		BaseURL:          workerBaseURL(s.cfg),
		HardwareSKU:      strings.TrimSpace(s.cfg.HardwareSKU),
		TotalCores:       s.cfg.TotalCores,
		TotalMemoryMiB:   s.cfg.TotalMemoryMiB,
		MaxLiveSandboxes: s.cfg.MaxLiveSandboxes,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	token, err := s.newInternalJWT()
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	responseBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("registration rejected: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(responseBytes)))
	}
	return nil
}

func (s *Service) deregisterFromBroker(ctx context.Context) error {
	target, err := url.JoinPath(strings.TrimSpace(s.cfg.BrokerControlURL), "/internal/workers", s.cfg.WorkerID, "registration")
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, target, nil)
	if err != nil {
		return err
	}
	token, err := s.newInternalJWT()
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("deregister rejected: status=%d", resp.StatusCode)
	}
	return nil
}

func (s *Service) emitReadyVMSnapshot() {
	s.mu.Lock()
	events := make([]model.WorkerVMEvent, 0, len(s.vms))
	for localVMID, record := range s.vms {
		record.mu.Lock()
		if record.state == vmStateReady {
			events = append(events, model.WorkerVMEvent{
				Event:          model.WorkerVMEventReady,
				LocalVMID:      localVMID,
				Virtualization: record.tuple.Virtualization,
				Image:          record.tuple.Image,
				CPU:            record.tuple.CPU,
				Timestamp:      s.cfg.Clock().UTC(),
			})
		}
		record.mu.Unlock()
	}
	s.mu.Unlock()
	for _, event := range events {
		s.emitVMEvent(context.Background(), event)
	}
}

func workerBaseURL(cfg Config) string {
	if cfg.AdvertiseURL != "" {
		return cfg.AdvertiseURL
	}
	host := strings.TrimSpace(cfg.Hostname)
	if host == "" {
		host = cfg.WorkerID
	}
	return "http://" + host + ":8081"
}

func (s *Service) emitVMEvent(ctx context.Context, event model.WorkerVMEvent) {
	baseURL := strings.TrimSpace(s.cfg.BrokerControlURL)
	if baseURL == "" {
		return
	}
	target, err := url.JoinPath(baseURL, "/internal/workers", s.cfg.WorkerID, "vm-events")
	if err != nil {
		s.cfg.Logger.Warn("failed to build worker vm event callback url", "error", err)
		return
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = s.cfg.Clock().UTC()
	}
	body, err := json.Marshal(event)
	if err != nil {
		s.cfg.Logger.Warn("failed to encode worker vm event", "error", err)
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		s.cfg.Logger.Warn("failed to build worker vm event request", "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	token, err := s.newInternalJWT()
	if err != nil {
		s.cfg.Logger.Warn("failed to sign worker vm event jwt", "error", err)
		return
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		s.cfg.Logger.Warn("worker vm event callback failed", "event", event.Event, "error", err)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		s.cfg.Logger.Warn("worker vm event callback rejected", "event", event.Event, "status_code", resp.StatusCode)
	}
}

func (s *Service) newInternalJWT() (string, error) {
	if s.cfg.InternalJWTSecret == "" {
		return "", nil
	}
	now := s.cfg.Clock().UTC()
	claims := jwt.RegisteredClaims{
		Subject:   s.cfg.WorkerID,
		Issuer:    s.cfg.InternalJWTIssuer,
		Audience:  jwt.ClaimStrings{s.cfg.InternalJWTAudience},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(45 * time.Second)),
		ID:        ulid.Make().String(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.cfg.InternalJWTSecret))
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

func normalizeTuple(tuple warm.Tuple) warm.Tuple {
	tuple.Virtualization = strings.TrimSpace(tuple.Virtualization)
	tuple.Image = strings.TrimSpace(tuple.Image)
	if tuple.Virtualization == "" {
		tuple.Virtualization = "vetu"
	}
	if tuple.CPU <= 0 {
		tuple.CPU = 1
	}
	return tuple
}

var (
	errSandboxNotFound   = errors.New("sandbox not found")
	errOwnershipMismatch = errors.New("sandbox ownership mismatch")
)

func (s *Service) getOwnedSandbox(principal auth.Principal, sandboxID string) (*sandboxState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sbx, ok := s.sandboxes[sandboxID]
	if !ok {
		return nil, errSandboxNotFound
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
		return errOwnershipMismatch
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
	case errors.Is(err, errSandboxNotFound):
		s.writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, errOwnershipMismatch):
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

