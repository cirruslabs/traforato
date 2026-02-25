package modes_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fedor/traforato/internal/auth"
	"github.com/fedor/traforato/internal/broker"
	"github.com/fedor/traforato/internal/worker"
)

func TestMissingJWTSecretSwitchesBrokerAndWorkerToDevNoAuthMode(t *testing.T) {
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	devValidator := auth.NewValidator("", "traforato", "traforato-api", func() time.Time { return now })

	brokerSvc := broker.NewService(broker.Config{
		Validator: devValidator,
		Clock:     func() time.Time { return now },
	})
	brokerSvc.RegisterWorker(broker.Worker{
		WorkerID:  "worker-a",
		Hostname:  "worker-a.local",
		BaseURL:   "http://worker-a.local:8081",
		Available: true,
	})

	brokerBody, _ := json.Marshal(map[string]any{"image": "ubuntu:24.04", "cpu": 1})
	brokerReq := httptest.NewRequest(http.MethodPost, "/sandboxes", bytes.NewReader(brokerBody))
	brokerRR := httptest.NewRecorder()
	brokerSvc.Handler().ServeHTTP(brokerRR, brokerReq)
	if brokerRR.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected broker 307 in dev no-auth mode, got %d body=%s", brokerRR.Code, brokerRR.Body.String())
	}

	workerSvc := worker.NewService(worker.Config{
		Hostname:       "worker-a.local",
		Validator:      devValidator,
		Clock:          func() time.Time { return now },
		TotalCores:     4,
		TotalMemoryMiB: 4096,
	})
	workerBody, _ := json.Marshal(map[string]any{"image": "ubuntu:24.04", "cpu": 1})
	workerReq := httptest.NewRequest(http.MethodPost, "/sandboxes", bytes.NewReader(workerBody))
	workerRR := httptest.NewRecorder()
	workerSvc.Handler().ServeHTTP(workerRR, workerReq)
	if workerRR.Code != http.StatusCreated {
		t.Fatalf("expected worker 201 in dev no-auth mode, got %d body=%s", workerRR.Code, workerRR.Body.String())
	}
}
