package broker

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/fedor/traforato/internal/auth"
	"github.com/golang-jwt/jwt/v5"
)

func makeBrokerJWT(t *testing.T, secret, jti string, now time.Time) string {
	t.Helper()
	claims := jwt.MapClaims{
		"client_id": "client-a",
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

func makeInternalWorkerJWT(t *testing.T, secret, issuer, workerID, jti string, now time.Time) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": issuer,
		"aud": []string{"traforato-internal"},
		"sub": workerID,
		"exp": now.Add(45 * time.Second).Unix(),
		"iat": now.Unix(),
		"jti": jti,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("SignedString(): %v", err)
	}
	return signed
}

func TestSandboxRoutesRedirectWithoutJWTValidation(t *testing.T) {
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	service := NewService(Config{
		BrokerID:  "broker_local",
		Validator: auth.NewValidator("secret", "traforato", "traforato-api", func() time.Time { return now }),
		Clock:     func() time.Time { return now },
	})
	service.RegisterWorker(Worker{
		WorkerID:  "worker_a",
		Hostname:  "worker-a.local",
		BaseURL:   "http://worker-a.local:8081",
		Available: true,
	})

	sandboxID := "sbx-broker_local-worker_a-550e8400-e29b-41d4-a716-446655440000"
	req := httptest.NewRequest(http.MethodGet, "/sandboxes/"+sandboxID, nil)
	rr := httptest.NewRecorder()

	service.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected 307, got %d body=%s", rr.Code, rr.Body.String())
	}
	if location := rr.Header().Get("Location"); location != "http://worker-a.local:8081/sandboxes/"+sandboxID {
		t.Fatalf("unexpected redirect location: %s", location)
	}
}

func TestCreateEndpointStillValidatesJWTInProd(t *testing.T) {
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	service := NewService(Config{
		BrokerID:  "broker_local",
		Validator: auth.NewValidator("secret", "traforato", "traforato-api", func() time.Time { return now }),
		Clock:     func() time.Time { return now },
	})
	service.RegisterWorker(Worker{
		WorkerID:  "worker_a",
		Hostname:  "worker-a.local",
		BaseURL:   "http://worker-a.local:8081",
		Available: true,
	})

	body, _ := json.Marshal(map[string]any{"image": "ubuntu:24.04", "cpu": 1})
	req := httptest.NewRequest(http.MethodPost, "/sandboxes", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	service.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when token missing, got %d", rr.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/sandboxes", bytes.NewReader(body))
	req2.Header.Set("Authorization", "Bearer "+makeBrokerJWT(t, "secret", "jti-1", now))
	rr2 := httptest.NewRecorder()
	service.Handler().ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected 307 with valid JWT, got %d body=%s", rr2.Code, rr2.Body.String())
	}
}

func TestCreateEndpointTargetsRequestedHardwareSKU(t *testing.T) {
	now := time.Now().UTC()
	service := NewService(Config{
		BrokerID:  "broker_local",
		Validator: auth.NewValidator("secret", "traforato", "traforato-api", func() time.Time { return now }),
		Clock:     func() time.Time { return now },
	})
	service.RegisterWorker(Worker{
		WorkerID:    "worker_a",
		Hostname:    "worker-a.local",
		BaseURL:     "http://worker-a.local:8081",
		HardwareSKU: "cpu-standard",
		Available:   true,
	})
	service.RegisterWorker(Worker{
		WorkerID:    "worker_b",
		Hostname:    "worker-b.local",
		BaseURL:     "http://worker-b.local:8081",
		HardwareSKU: "gpu-a100",
		Available:   true,
	})

	body, _ := json.Marshal(map[string]any{
		"image":        "ubuntu:24.04",
		"cpu":          1,
		"hardware_sku": "gpu-a100",
	})
	req := httptest.NewRequest(http.MethodPost, "/sandboxes", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+makeBrokerJWT(t, "secret", "jti-hw-1", now))
	rr := httptest.NewRecorder()
	service.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected 307 with matching hardware_sku, got %d body=%s", rr.Code, rr.Body.String())
	}
	if location := rr.Header().Get("Location"); location != "http://worker-b.local:8081/sandboxes" {
		t.Fatalf("expected redirect to gpu worker, got %s", location)
	}
}

func TestCreateEndpointReturns503WhenHardwareSKUUnavailable(t *testing.T) {
	now := time.Now().UTC()
	service := NewService(Config{
		BrokerID:  "broker_local",
		Validator: auth.NewValidator("secret", "traforato", "traforato-api", func() time.Time { return now }),
		Clock:     func() time.Time { return now },
	})
	service.RegisterWorker(Worker{
		WorkerID:    "worker_a",
		Hostname:    "worker-a.local",
		BaseURL:     "http://worker-a.local:8081",
		HardwareSKU: "cpu-standard",
		Available:   true,
	})

	body, _ := json.Marshal(map[string]any{
		"image":        "ubuntu:24.04",
		"cpu":          1,
		"hardware_sku": "gpu-h100",
	})
	req := httptest.NewRequest(http.MethodPost, "/sandboxes", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+makeBrokerJWT(t, "secret", "jti-hw-2", now))
	rr := httptest.NewRecorder()
	service.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when hardware_sku is unavailable, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestMalformedAndUnknownSandboxRoutes(t *testing.T) {
	service := NewService(Config{
		BrokerID:  "broker_local",
		Validator: auth.NewValidator("", "", "", nil),
	})
	service.RegisterWorker(Worker{
		WorkerID:  "worker_a",
		Hostname:  "worker-a.local",
		BaseURL:   "http://worker-a.local:8081",
		Available: true,
	})

	malformedReq := httptest.NewRequest(http.MethodGet, "/sandboxes/not-an-id", nil)
	malformedRR := httptest.NewRecorder()
	service.Handler().ServeHTTP(malformedRR, malformedReq)
	if malformedRR.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed id, got %d", malformedRR.Code)
	}

	unknownReq := httptest.NewRequest(http.MethodGet, "/sandboxes/sbx-broker_local-worker_unknown-550e8400-e29b-41d4-a716-446655440000", nil)
	unknownRR := httptest.NewRecorder()
	service.Handler().ServeHTTP(unknownRR, unknownReq)
	if unknownRR.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown worker id, got %d", unknownRR.Code)
	}

	brokerMismatchReq := httptest.NewRequest(http.MethodGet, "/sandboxes/sbx-broker_other-worker_a-550e8400-e29b-41d4-a716-446655440000", nil)
	brokerMismatchRR := httptest.NewRecorder()
	service.Handler().ServeHTTP(brokerMismatchRR, brokerMismatchReq)
	if brokerMismatchRR.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for broker mismatch, got %d", brokerMismatchRR.Code)
	}
}

func TestCreateEndpointUsesReadyVMPlacementHint(t *testing.T) {
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	service := NewService(Config{
		BrokerID:            "broker_local",
		Validator:           auth.NewValidator("secret", "traforato", "traforato-api", func() time.Time { return now }),
		Clock:               func() time.Time { return now },
		InternalJWTSecret:   "secret",
		InternalJWTIssuer:   "traforato",
		InternalJWTAudience: "traforato-internal",
	})
	service.RegisterWorker(Worker{
		WorkerID:    "worker_a",
		Hostname:    "worker-a.local",
		BaseURL:     "http://worker-a.local:8081",
		HardwareSKU: "cpu-standard",
		Available:   true,
	})
	eventBody, _ := json.Marshal(map[string]any{
		"event":          "ready",
		"local_vm_id":    "550e8400-e29b-41d4-a716-446655440000",
		"virtualization": "vetu",
		"image":          "ubuntu:24.04",
		"cpu":            2,
		"timestamp":      now.Format(time.RFC3339Nano),
	})
	eventReq := httptest.NewRequest(http.MethodPost, "/internal/workers/worker_a/vm-events", bytes.NewReader(eventBody))
	eventReq.Header.Set("Authorization", "Bearer "+makeInternalWorkerJWT(t, "secret", "traforato", "worker_a", "jti-vm-1", now))
	eventRR := httptest.NewRecorder()
	service.Handler().ServeHTTP(eventRR, eventReq)
	if eventRR.Code != http.StatusNoContent {
		t.Fatalf("expected 204 vm event, got %d body=%s", eventRR.Code, eventRR.Body.String())
	}

	createBody, _ := json.Marshal(map[string]any{
		"image":          "ubuntu:24.04",
		"cpu":            2,
		"virtualization": "vetu",
	})
	createReq := httptest.NewRequest(http.MethodPost, "/sandboxes", bytes.NewReader(createBody))
	createReq.Header.Set("Authorization", "Bearer "+makeBrokerJWT(t, "secret", "jti-ready-placement", now))
	createRR := httptest.NewRecorder()
	service.Handler().ServeHTTP(createRR, createReq)
	if createRR.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected 307 for ready placement, got %d body=%s", createRR.Code, createRR.Body.String())
	}
	location := createRR.Header().Get("Location")
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("Parse(location): %v", err)
	}
	if parsed.Host != "worker-a.local:8081" || parsed.Path != "/sandboxes" {
		t.Fatalf("unexpected redirect target: %s", location)
	}
	if got := parsed.Query().Get("local_vm_id"); got != "550e8400-e29b-41d4-a716-446655440000" {
		t.Fatalf("expected local_vm_id in redirect, got %q location=%s", got, location)
	}
}

func TestCreateEndpointPlacementRetryBudget(t *testing.T) {
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	service := NewService(Config{
		BrokerID:          "broker_local",
		Validator:         auth.NewValidator("secret", "traforato", "traforato-api", func() time.Time { return now }),
		Clock:             func() time.Time { return now },
		PlacementRetryMax: 1,
	})
	service.RegisterWorker(Worker{
		WorkerID:  "worker_a",
		Hostname:  "worker-a.local",
		BaseURL:   "http://worker-a.local:8081",
		Available: true,
	})

	body, _ := json.Marshal(map[string]any{"image": "ubuntu:24.04", "cpu": 1})
	req := httptest.NewRequest(http.MethodPost, "/sandboxes?placement_retry=2", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+makeBrokerJWT(t, "secret", "jti-retry-exhausted", now))
	rr := httptest.NewRecorder()
	service.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 after retry budget exhausted, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestInternalVMEventAuthAndSubjectMatch(t *testing.T) {
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	service := NewService(Config{
		BrokerID:            "broker_local",
		Validator:           auth.NewValidator("secret", "traforato", "traforato-api", func() time.Time { return now }),
		Clock:               func() time.Time { return now },
		InternalJWTSecret:   "secret",
		InternalJWTIssuer:   "traforato",
		InternalJWTAudience: "traforato-internal",
	})
	service.RegisterWorker(Worker{
		WorkerID:  "worker_a",
		Hostname:  "worker-a.local",
		BaseURL:   "http://worker-a.local:8081",
		Available: true,
	})

	body := []byte(`{"event":"ready","local_vm_id":"550e8400-e29b-41d4-a716-446655440000","virtualization":"vetu","image":"ubuntu:24.04","cpu":1}`)
	missingAuthReq := httptest.NewRequest(http.MethodPost, "/internal/workers/worker_a/vm-events", bytes.NewReader(body))
	missingAuthRR := httptest.NewRecorder()
	service.Handler().ServeHTTP(missingAuthRR, missingAuthReq)
	if missingAuthRR.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing auth, got %d", missingAuthRR.Code)
	}

	wrongSubReq := httptest.NewRequest(http.MethodPost, "/internal/workers/worker_a/vm-events", bytes.NewReader(body))
	wrongSubReq.Header.Set("Authorization", "Bearer "+makeInternalWorkerJWT(t, "secret", "traforato", "worker_b", "jti-vm-wrong-sub", now))
	wrongSubRR := httptest.NewRecorder()
	service.Handler().ServeHTTP(wrongSubRR, wrongSubReq)
	if wrongSubRR.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for sub mismatch, got %d", wrongSubRR.Code)
	}

	validReq := httptest.NewRequest(http.MethodPost, "/internal/workers/worker_a/vm-events", bytes.NewReader(body))
	validReq.Header.Set("Authorization", "Bearer "+makeInternalWorkerJWT(t, "secret", "traforato", "worker_a", "jti-vm-valid", now))
	validRR := httptest.NewRecorder()
	service.Handler().ServeHTTP(validRR, validReq)
	if validRR.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for valid internal event auth, got %d body=%s", validRR.Code, validRR.Body.String())
	}
}

func TestInternalVMEventAllowsDevModeWithoutAuth(t *testing.T) {
	service := NewService(Config{
		BrokerID:  "broker_local",
		Validator: auth.NewValidator("", "", "", nil),
	})
	service.RegisterWorker(Worker{
		WorkerID:  "worker_a",
		Hostname:  "worker-a.local",
		BaseURL:   "http://worker-a.local:8081",
		Available: true,
	})

	body := []byte(`{"event":"ready","local_vm_id":"550e8400-e29b-41d4-a716-446655440000","virtualization":"vetu","image":"ubuntu:24.04","cpu":1}`)
	req := httptest.NewRequest(http.MethodPost, "/internal/workers/worker_a/vm-events", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	service.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204 in dev mode without auth, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestInternalVMEventRejectsWrongAudience(t *testing.T) {
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	service := NewService(Config{
		BrokerID:            "broker_local",
		Validator:           auth.NewValidator("secret", "traforato", "traforato-api", func() time.Time { return now }),
		Clock:               func() time.Time { return now },
		InternalJWTSecret:   "secret",
		InternalJWTIssuer:   "traforato",
		InternalJWTAudience: "traforato-internal",
	})
	service.RegisterWorker(Worker{
		WorkerID:  "worker_a",
		Hostname:  "worker-a.local",
		BaseURL:   "http://worker-a.local:8081",
		Available: true,
	})

	claims := jwt.MapClaims{
		"iss": "traforato",
		"aud": []string{"traforato-api"},
		"sub": "worker_a",
		"exp": now.Add(45 * time.Second).Unix(),
		"iat": now.Unix(),
		"jti": "jti-vm-wrong-aud",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte("secret"))
	if err != nil {
		t.Fatalf("SignedString(): %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/internal/workers/worker_a/vm-events", strings.NewReader(`{"event":"ready","local_vm_id":"550e8400-e29b-41d4-a716-446655440000","virtualization":"vetu","image":"ubuntu:24.04","cpu":1}`))
	req.Header.Set("Authorization", "Bearer "+signed)
	rr := httptest.NewRecorder()
	service.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong audience, got %d", rr.Code)
	}
}
