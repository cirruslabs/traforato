package modes_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fedor/traforetto/internal/auth"
	"github.com/fedor/traforetto/internal/controller"
	"github.com/fedor/traforetto/internal/worker"
)

func TestMissingJWTSecretSwitchesControllerAndWorkerToDevNoAuthMode(t *testing.T) {
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	devValidator := auth.NewValidator("", "traforetto", "traforetto-api", func() time.Time { return now })

	controllerSvc := controller.NewService(controller.Config{
		Validator: devValidator,
		Clock:     func() time.Time { return now },
	})
	controllerSvc.RegisterWorker(controller.Worker{
		WorkerID:  "worker-a",
		Hostname:  "worker-a.local",
		BaseURL:   "http://worker-a.local:8081",
		Available: true,
	})

	controllerBody, _ := json.Marshal(map[string]any{"image": "ubuntu:24.04", "cpu": 1})
	controllerReq := httptest.NewRequest(http.MethodPost, "/sandboxes", bytes.NewReader(controllerBody))
	controllerRR := httptest.NewRecorder()
	controllerSvc.Handler().ServeHTTP(controllerRR, controllerReq)
	if controllerRR.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected controller 307 in dev no-auth mode, got %d body=%s", controllerRR.Code, controllerRR.Body.String())
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
