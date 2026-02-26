package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fedor/traforato/internal/auth"
	"github.com/fedor/traforato/internal/model"
	"github.com/fedor/traforato/internal/sandboxid"
	"github.com/fedor/traforato/internal/telemetry"
	"github.com/fedor/traforato/internal/warm"
	"github.com/golang-jwt/jwt/v5"
)

func makeJWT(t *testing.T, secret, clientID, jti string, now time.Time) string {
	t.Helper()
	claims := jwt.MapClaims{
		"client_id": clientID,
		"iss":       "traforato",
		"aud":       []string{"traforato-api"},
		"exp":       now.Add(5 * time.Minute).Unix(),
		"iat":       now.Add(-1 * time.Minute).Unix(),
		"jti":       jti,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("SignedString(): %v", err)
	}
	return signed
}

func newRequest(t *testing.T, method, path string, body any) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("Encode body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	return req
}

func decodeJSON(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("Unmarshal response: %v body=%s", err, rr.Body.String())
	}
	return payload
}

func TestWorkerDevModeAllowsNoAuth(t *testing.T) {
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	svc := NewService(Config{
		BrokerID:       "broker_local",
		WorkerID:       "worker_a",
		Hostname:       "worker-a.local",
		Validator:      auth.NewValidator("", "", "", func() time.Time { return now }),
		Clock:          func() time.Time { return now },
		TotalCores:     4,
		TotalMemoryMiB: 4096,
	})
	handler := svc.Handler()

	createReq := newRequest(t, http.MethodPost, "/sandboxes", map[string]any{"image": "ubuntu:24.04", "cpu": 2})
	createRR := httptest.NewRecorder()
	handler.ServeHTTP(createRR, createReq)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", createRR.Code, createRR.Body.String())
	}
	createPayload := decodeJSON(t, createRR)
	if _, exists := createPayload["worker_hash"]; exists {
		t.Fatal("expected worker_hash to be omitted from create payload")
	}
	sandboxID := createPayload["sandbox_id"].(string)

	getReq := newRequest(t, http.MethodGet, "/sandboxes/"+sandboxID, nil)
	getRR := httptest.NewRecorder()
	handler.ServeHTTP(getRR, getReq)
	if getRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", getRR.Code, getRR.Body.String())
	}
}

func TestWorkerProdModeEnforcesOwnership(t *testing.T) {
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	validator := auth.NewValidator("secret", "traforato", "traforato-api", func() time.Time { return now })
	svc := NewService(Config{
		BrokerID:       "broker_local",
		WorkerID:       "worker_a",
		Hostname:       "worker-a.local",
		Validator:      validator,
		Clock:          func() time.Time { return now },
		TotalCores:     4,
		TotalMemoryMiB: 4096,
	})
	handler := svc.Handler()

	createReq := newRequest(t, http.MethodPost, "/sandboxes", map[string]any{"image": "ubuntu:24.04", "cpu": 1})
	createReq.Header.Set("Authorization", "Bearer "+makeJWT(t, "secret", "client-a", "jti-1", now))
	createRR := httptest.NewRecorder()
	handler.ServeHTTP(createRR, createReq)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", createRR.Code, createRR.Body.String())
	}
	createPayload := decodeJSON(t, createRR)
	sandboxID := createPayload["sandbox_id"].(string)

	getOwnerReq := newRequest(t, http.MethodGet, "/sandboxes/"+sandboxID, nil)
	getOwnerReq.Header.Set("Authorization", "Bearer "+makeJWT(t, "secret", "client-a", "jti-2", now))
	getOwnerRR := httptest.NewRecorder()
	handler.ServeHTTP(getOwnerRR, getOwnerReq)
	if getOwnerRR.Code != http.StatusOK {
		t.Fatalf("expected owner to read sandbox with 200, got %d body=%s", getOwnerRR.Code, getOwnerRR.Body.String())
	}

	getOtherReq := newRequest(t, http.MethodGet, "/sandboxes/"+sandboxID, nil)
	getOtherReq.Header.Set("Authorization", "Bearer "+makeJWT(t, "secret", "client-b", "jti-3", now))
	getOtherRR := httptest.NewRecorder()
	handler.ServeHTTP(getOtherRR, getOtherReq)
	if getOtherRR.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for different client, got %d body=%s", getOtherRR.Code, getOtherRR.Body.String())
	}
}

func TestFirstExecTTIMetricEmittedOncePerSandbox(t *testing.T) {
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	telemetryRecorder := telemetry.NewRecorder(auth.ModeProd)
	t.Cleanup(func() { _ = telemetryRecorder.Shutdown(context.Background()) })

	validator := auth.NewValidator("secret", "traforato", "traforato-api", func() time.Time { return now })
	svc := NewService(Config{
		BrokerID:       "broker_local",
		WorkerID:       "worker_a",
		Hostname:       "worker-a.local",
		Validator:      validator,
		Telemetry:      telemetryRecorder,
		Clock:          func() time.Time { return now },
		TotalCores:     4,
		TotalMemoryMiB: 4096,
	})
	handler := svc.Handler()

	createReq := newRequest(t, http.MethodPost, "/sandboxes", map[string]any{"image": "ubuntu:24.04", "cpu": 1})
	createReq.Header.Set("Authorization", "Bearer "+makeJWT(t, "secret", "client-a", "jti-create", now))
	createRR := httptest.NewRecorder()
	handler.ServeHTTP(createRR, createReq)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("expected 201 create, got %d body=%s", createRR.Code, createRR.Body.String())
	}
	sandboxID := decodeJSON(t, createRR)["sandbox_id"].(string)

	execReq1 := newRequest(t, http.MethodPost, "/sandboxes/"+sandboxID+"/exec", map[string]any{"command": "echo hi"})
	execReq1.Header.Set("Authorization", "Bearer "+makeJWT(t, "secret", "client-a", "jti-exec-1", now))
	execRR1 := httptest.NewRecorder()
	handler.ServeHTTP(execRR1, execReq1)
	if execRR1.Code != http.StatusAccepted {
		t.Fatalf("expected 202 first exec, got %d", execRR1.Code)
	}

	execReq2 := newRequest(t, http.MethodPost, "/sandboxes/"+sandboxID+"/exec", map[string]any{"command": "echo hi again"})
	execReq2.Header.Set("Authorization", "Bearer "+makeJWT(t, "secret", "client-a", "jti-exec-2", now))
	execRR2 := httptest.NewRecorder()
	handler.ServeHTTP(execRR2, execReq2)
	if execRR2.Code != http.StatusAccepted {
		t.Fatalf("expected 202 second exec, got %d", execRR2.Code)
	}

	ttiSamples := 0
	for _, sample := range telemetryRecorder.Samples() {
		if sample.Name == telemetry.MetricWorkerFirstExecTTI {
			ttiSamples++
		}
	}
	if ttiSamples != 1 {
		t.Fatalf("expected one TTI sample, got %d", ttiSamples)
	}
}

func TestCreateSandboxClaimsHintedVMAndEmitsClaimedEvent(t *testing.T) {
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	var claimedEvent model.WorkerVMEvent
	var authHeader string
	callback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("ReadAll(): %v", err)
		}
		if err := json.Unmarshal(body, &claimedEvent); err != nil {
			t.Fatalf("Unmarshal callback payload: %v body=%s", err, string(body))
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer callback.Close()

	validator := auth.NewValidator("secret", "traforato", "traforato-api", func() time.Time { return now })
	svc := NewService(Config{
		BrokerID:            "broker_local",
		WorkerID:            "worker_a",
		BrokerControlURL:    callback.URL,
		Hostname:            "worker-a.local",
		Validator:           validator,
		Clock:               func() time.Time { return now },
		TotalCores:          4,
		TotalMemoryMiB:      4096,
		InternalJWTSecret:   "secret",
		InternalJWTIssuer:   "traforato",
		InternalJWTAudience: "traforato-internal",
	})
	tuple := warm.Tuple{Virtualization: "vetu", Image: "ubuntu:24.04", CPU: 1}
	svc.mu.Lock()
	svc.vms["550e8400-e29b-41d4-a716-446655440000"] = &vmRecord{
		state: vmStateReady,
		tuple: tuple,
	}
	svc.mu.Unlock()

	handler := svc.Handler()
	createReq := newRequest(t, http.MethodPost, "/sandboxes?local_vm_id=550e8400-e29b-41d4-a716-446655440000", map[string]any{
		"image":          "ubuntu:24.04",
		"cpu":            1,
		"virtualization": "vetu",
	})
	createReq.Header.Set("Authorization", "Bearer "+makeJWT(t, "secret", "client-a", "jti-claim-hint", now))
	createRR := httptest.NewRecorder()
	handler.ServeHTTP(createRR, createReq)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("expected 201 for hinted vm claim, got %d body=%s", createRR.Code, createRR.Body.String())
	}
	sandboxID := decodeJSON(t, createRR)["sandbox_id"].(string)
	parsed, err := sandboxid.Parse(sandboxID)
	if err != nil {
		t.Fatalf("Parse(sandbox_id): %v", err)
	}
	if parsed.LocalVMID != "550e8400-e29b-41d4-a716-446655440000" {
		t.Fatalf("expected sandbox_id to use hinted local vm id, got %q", parsed.LocalVMID)
	}
	if claimedEvent.Event != model.WorkerVMEventClaimed {
		t.Fatalf("expected claimed callback event, got %q", claimedEvent.Event)
	}
	if claimedEvent.LocalVMID != "550e8400-e29b-41d4-a716-446655440000" {
		t.Fatalf("expected claimed callback local vm id, got %q", claimedEvent.LocalVMID)
	}
	if !strings.HasPrefix(authHeader, "Bearer ") {
		t.Fatalf("expected bearer auth header on callback, got %q", authHeader)
	}
	token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	claims := &jwt.RegisteredClaims{}
	parsedToken, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		return []byte("secret"), nil
	}, jwt.WithAudience("traforato-internal"), jwt.WithIssuer("traforato"), jwt.WithTimeFunc(func() time.Time { return now }))
	if err != nil || !parsedToken.Valid {
		t.Fatalf("expected valid callback jwt, err=%v", err)
	}
	if claims.Subject != "worker_a" {
		t.Fatalf("expected sub=worker_a, got %q", claims.Subject)
	}
}

func TestCreateSandboxRedirectsBackToBrokerOnHintConflict(t *testing.T) {
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	validator := auth.NewValidator("secret", "traforato", "traforato-api", func() time.Time { return now })
	svc := NewService(Config{
		BrokerID:         "broker_local",
		WorkerID:         "worker_a",
		BrokerControlURL: "http://broker.example.com",
		Hostname:         "worker-a.local",
		Validator:        validator,
		Clock:            func() time.Time { return now },
		TotalCores:       4,
		TotalMemoryMiB:   4096,
	})
	handler := svc.Handler()
	createReq := newRequest(t, http.MethodPost, "/sandboxes?local_vm_id=550e8400-e29b-41d4-a716-446655440000&placement_retry=1", map[string]any{
		"image":          "ubuntu:24.04",
		"cpu":            1,
		"virtualization": "vetu",
	})
	createReq.Header.Set("Authorization", "Bearer "+makeJWT(t, "secret", "client-a", "jti-hot-potato", now))
	createRR := httptest.NewRecorder()
	handler.ServeHTTP(createRR, createReq)
	if createRR.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected 307 for hinted vm conflict, got %d body=%s", createRR.Code, createRR.Body.String())
	}
	if got := createRR.Header().Get("Location"); got != "http://broker.example.com/sandboxes?placement_retry=2" {
		t.Fatalf("unexpected redirect location: %s", got)
	}
}
