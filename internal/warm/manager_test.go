package warm

import (
	"errors"
	"testing"
	"time"
)

type fakeRunner struct {
	failWarmup bool
	calls      []string
}

func (f *fakeRunner) Provision(Tuple) error {
	f.calls = append(f.calls, "provision")
	return nil
}

func (f *fakeRunner) Connect(Tuple) error {
	f.calls = append(f.calls, "connect")
	return nil
}

func (f *fakeRunner) Warmup(Tuple, string, time.Duration) error {
	f.calls = append(f.calls, "warmup")
	if f.failWarmup {
		return errors.New("warmup failed")
	}
	return nil
}

func (f *fakeRunner) Reconnect(Tuple) error {
	f.calls = append(f.calls, "reconnect")
	return nil
}

func TestComputeTargetsGuaranteesHottestTuple(t *testing.T) {
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	hot := Tuple{Virtualization: "vetu", Image: "ubuntu:24.04", CPU: 2}
	cold := Tuple{Virtualization: "vetu", Image: "alpine:3.20", CPU: 1}
	events := []DemandEvent{
		{Tuple: hot, Timestamp: now.Add(-5 * time.Minute)},
		{Tuple: hot, Timestamp: now.Add(-10 * time.Minute)},
		{Tuple: cold, Timestamp: now.Add(-50 * time.Minute)},
	}

	targets := ComputeTargets(events, 1, now)
	if targets[hot] != 1 {
		t.Fatalf("expected hottest tuple target to be 1, got %+v", targets)
	}
}

func TestWarmupGatingReadiness(t *testing.T) {
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	tuple := Tuple{Virtualization: "vetu", Image: "ubuntu:24.04", CPU: 2}

	failRunner := &fakeRunner{failWarmup: true}
	failMgr := NewManager(func() time.Time { return now }, failRunner)
	failMgr.SetTupleConfig(tuple, 1, "echo warm", 30)
	if err := failMgr.EnsureReady(tuple); err == nil {
		t.Fatal("expected warmup error, got nil")
	}
	if got := failMgr.ReadyCount(tuple); got != 0 {
		t.Fatalf("expected ready count 0 after failure, got %d", got)
	}

	okRunner := &fakeRunner{}
	okMgr := NewManager(func() time.Time { return now }, okRunner)
	okMgr.SetTupleConfig(tuple, 1, "echo warm", 30)
	if err := okMgr.EnsureReady(tuple); err != nil {
		t.Fatalf("EnsureReady() unexpected error: %v", err)
	}
	if got := okMgr.ReadyCount(tuple); got != 1 {
		t.Fatalf("expected ready count 1 after success, got %d", got)
	}
}

func TestEnsureReadyRequiresRunner(t *testing.T) {
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	tuple := Tuple{Virtualization: "vetu", Image: "ubuntu:24.04", CPU: 2}

	mgr := NewManager(func() time.Time { return now }, nil)
	mgr.SetTupleConfig(tuple, 1, "echo warm", 30)

	err := mgr.EnsureReady(tuple)
	if !errors.Is(err, ErrRunnerUnavailable) {
		t.Fatalf("expected ErrRunnerUnavailable, got %v", err)
	}

	if got := mgr.ReadyCount(tuple); got != 0 {
		t.Fatalf("expected ready count 0 when runner is missing, got %d", got)
	}
}

func TestSSHDropTriggersRewarm(t *testing.T) {
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	tuple := Tuple{Virtualization: "vetu", Image: "ubuntu:24.04", CPU: 2}
	runner := &fakeRunner{}
	mgr := NewManager(func() time.Time { return now }, runner)
	mgr.SetTupleConfig(tuple, 1, "echo warm", 30)
	if err := mgr.EnsureReady(tuple); err != nil {
		t.Fatalf("EnsureReady() unexpected error: %v", err)
	}
	if got := mgr.ReadyCount(tuple); got != 1 {
		t.Fatalf("expected ready count 1 before drop, got %d", got)
	}

	if err := mgr.HandleSSHDrop(tuple); err != nil {
		t.Fatalf("HandleSSHDrop() unexpected error: %v", err)
	}
	if got := mgr.ReadyCount(tuple); got != 1 {
		t.Fatalf("expected ready count re-established to 1, got %d", got)
	}
	if len(runner.calls) < 8 {
		t.Fatalf("expected full warm cycle to run twice, calls=%v", runner.calls)
	}
}

func TestReadySnapshotReturnsCopy(t *testing.T) {
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	tuple := Tuple{Virtualization: "vetu", Image: "ubuntu:24.04", CPU: 2}
	runner := &fakeRunner{}
	mgr := NewManager(func() time.Time { return now }, runner)
	mgr.SetTupleConfig(tuple, 1, "echo warm", 30)
	if err := mgr.EnsureReady(tuple); err != nil {
		t.Fatalf("EnsureReady() unexpected error: %v", err)
	}

	snapshot := mgr.ReadySnapshot()
	if snapshot[tuple] != 1 {
		t.Fatalf("expected ready snapshot count 1, got %d", snapshot[tuple])
	}
	snapshot[tuple] = 100
	if mgr.ReadyCount(tuple) != 1 {
		t.Fatalf("expected manager state unchanged by snapshot mutation, got %d", mgr.ReadyCount(tuple))
	}
}
