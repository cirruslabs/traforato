package broker

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
