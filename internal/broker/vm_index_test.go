package broker

import (
	"testing"
	"time"

	"github.com/fedor/traforato/internal/auth"
	"github.com/fedor/traforato/internal/model"
	"github.com/fedor/traforato/internal/warm"
)

func TestVMIndexPopRemovesReadyEntry(t *testing.T) {
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	svc := NewService(Config{
		BrokerID:  "broker_local",
		Validator: auth.NewValidator("", "", "", func() time.Time { return now }),
		Clock:     func() time.Time { return now },
	})
	svc.RegisterWorker(Worker{
		WorkerID:  "worker_a",
		BaseURL:   "http://worker-a.local:8081",
		Available: true,
	})
	svc.mu.Lock()
	err := svc.applyVMEventLocked("worker_a", model.WorkerVMEvent{
		Event:          model.WorkerVMEventReady,
		LocalVMID:      "550e8400-e29b-41d4-a716-446655440000",
		Virtualization: "vetu",
		Image:          "ubuntu:24.04",
		CPU:            1,
		Timestamp:      now,
	})
	svc.mu.Unlock()
	if err != nil {
		t.Fatalf("applyVMEventLocked(): %v", err)
	}

	worker, vm, ok := svc.popReadyVM(warm.Tuple{Virtualization: "vetu", Image: "ubuntu:24.04", CPU: 1}, "")
	if !ok {
		t.Fatal("expected vm placement from ready index")
	}
	if worker.WorkerID != "worker_a" {
		t.Fatalf("expected worker_a, got %s", worker.WorkerID)
	}
	if vm.LocalVMID != "550e8400-e29b-41d4-a716-446655440000" {
		t.Fatalf("unexpected local vm id: %s", vm.LocalVMID)
	}
	if _, _, ok := svc.popReadyVM(warm.Tuple{Virtualization: "vetu", Image: "ubuntu:24.04", CPU: 1}, ""); ok {
		t.Fatal("expected ready vm to be removed after first pop")
	}
}

func TestVMIndexRejectsDuplicatePopAcrossConcurrentPlacement(t *testing.T) {
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	svc := NewService(Config{
		BrokerID:  "broker_local",
		Validator: auth.NewValidator("", "", "", func() time.Time { return now }),
		Clock:     func() time.Time { return now },
	})
	svc.RegisterWorker(Worker{
		WorkerID:  "worker_a",
		BaseURL:   "http://worker-a.local:8081",
		Available: true,
	})
	svc.mu.Lock()
	if err := svc.applyVMEventLocked("worker_a", model.WorkerVMEvent{
		Event:          model.WorkerVMEventReady,
		LocalVMID:      "550e8400-e29b-41d4-a716-446655440000",
		Virtualization: "vetu",
		Image:          "ubuntu:24.04",
		CPU:            1,
		Timestamp:      now,
	}); err != nil {
		t.Fatalf("applyVMEventLocked(): %v", err)
	}
	svc.mu.Unlock()

	results := make(chan bool, 2)
	for i := 0; i < 2; i++ {
		go func() {
			_, _, ok := svc.popReadyVM(warm.Tuple{Virtualization: "vetu", Image: "ubuntu:24.04", CPU: 1}, "")
			results <- ok
		}()
	}
	gotTrue := 0
	for i := 0; i < 2; i++ {
		if <-results {
			gotTrue++
		}
	}
	if gotTrue != 1 {
		t.Fatalf("expected exactly one successful pop, got %d", gotTrue)
	}
}
