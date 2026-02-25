package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fedor/traforetto/internal/auth"
	"github.com/fedor/traforetto/internal/telemetry"
	"github.com/golang-jwt/jwt/v5"
)

func makeJWT(t *testing.T, secret, clientID, jti string, now time.Time) string {
	t.Helper()
	claims := jwt.MapClaims{
		"client_id": clientID,
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
	validator := auth.NewValidator("secret", "traforetto", "traforetto-api", func() time.Time { return now })
	svc := NewService(Config{
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

	validator := auth.NewValidator("secret", "traforetto", "traforetto-api", func() time.Time { return now })
	svc := NewService(Config{
		WorkerID:       "worker-a",
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
