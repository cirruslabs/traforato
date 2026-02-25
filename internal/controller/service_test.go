package controller

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fedor/traforetto/internal/auth"
	"github.com/fedor/traforetto/internal/sandboxid"
	"github.com/golang-jwt/jwt/v5"
)

func makeControllerJWT(t *testing.T, secret, jti string, now time.Time) string {
	t.Helper()
	claims := jwt.MapClaims{
		"client_id": "client-a",
		"iss":       "traforetto",
		"aud":       []string{"traforetto-api"},
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
		Validator: auth.NewValidator("secret", "traforetto", "traforetto-api", func() time.Time { return now }),
		Clock:     func() time.Time { return now },
	})
	service.RegisterWorker(Worker{
		WorkerID:  "worker-a",
		Hostname:  "worker-a.local",
		BaseURL:   "http://worker-a.local:8081",
		Available: true,
	})

	hash := sandboxid.WorkerHash("worker-a.local")
	sandboxID := "sbx_" + hash + "_01HZYXW2A3BCDEF4GHJKMNPQRS"
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
		Validator: auth.NewValidator("secret", "traforetto", "traforetto-api", func() time.Time { return now }),
		Clock:     func() time.Time { return now },
	})
	service.RegisterWorker(Worker{
		WorkerID:  "worker-a",
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
	req2.Header.Set("Authorization", "Bearer "+makeControllerJWT(t, "secret", "jti-1", now))
	rr2 := httptest.NewRecorder()
	service.Handler().ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected 307 with valid JWT, got %d body=%s", rr2.Code, rr2.Body.String())
	}
}

func TestMalformedAndUnknownSandboxRoutes(t *testing.T) {
	service := NewService(Config{
		Validator: auth.NewValidator("", "", "", nil),
	})
	service.RegisterWorker(Worker{
		WorkerID:  "worker-a",
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

	unknownReq := httptest.NewRequest(http.MethodGet, "/sandboxes/sbx_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_01HZYXW2A3BCDEF4GHJKMNPQRS", nil)
	unknownRR := httptest.NewRecorder()
	service.Handler().ServeHTTP(unknownRR, unknownReq)
	if unknownRR.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown hash, got %d", unknownRR.Code)
	}
}
