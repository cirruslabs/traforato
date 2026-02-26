package sandboxid

import (
	"strings"
	"testing"
)

func TestParseValidID(t *testing.T) {
	id := "sbx-broker_local-worker_local-550e8400-e29b-41d4-a716-446655440000"
	parsed, err := Parse(id)
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if parsed.BrokerID != "broker_local" {
		t.Fatalf("unexpected broker id: %s", parsed.BrokerID)
	}
	if parsed.WorkerID != "worker_local" {
		t.Fatalf("unexpected worker id: %s", parsed.WorkerID)
	}
	if parsed.LocalVMID != "550e8400-e29b-41d4-a716-446655440000" {
		t.Fatalf("unexpected local vm id: %s", parsed.LocalVMID)
	}
}

func TestNewAndParseRoundtrip(t *testing.T) {
	id, err := New("broker_local", "worker_local", strings.NewReader(strings.Repeat("x", 32)))
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}
	if !strings.HasPrefix(id, "sbx-broker_local-worker_local-") {
		t.Fatalf("unexpected id prefix: %s", id)
	}
	parsed, err := Parse(id)
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if parsed.BrokerID != "broker_local" {
		t.Fatalf("unexpected broker id: %s", parsed.BrokerID)
	}
	if parsed.WorkerID != "worker_local" {
		t.Fatalf("unexpected worker id: %s", parsed.WorkerID)
	}
}

func TestParseRejectsMalformedID(t *testing.T) {
	if _, err := Parse("sbx-broker_local-worker_local-not-a-uuid"); err == nil {
		t.Fatal("expected malformed error")
	}
}

func TestParseRejectsOldFormat(t *testing.T) {
	oldID := "sbx_7f4ecf5b88c924f2c7f9f1e6ee629d8f_01HZYXW2A3BCDEF4GHJKMNPQRS"
	if _, err := Parse(oldID); err == nil {
		t.Fatal("expected malformed error for old format")
	}
}

func TestParseRejectsMissingPrefix(t *testing.T) {
	if _, err := Parse("broker_local-worker_local-550e8400-e29b-41d4-a716-446655440000"); err == nil {
		t.Fatal("expected malformed error")
	}
}

func TestParseRejectsNonV4UUID(t *testing.T) {
	if _, err := Parse("sbx-broker_local-worker_local-550e8400-e29b-11d4-a716-446655440000"); err == nil {
		t.Fatal("expected malformed error for non-v4 uuid")
	}
}

func TestParseRejectsNonCanonicalUUID(t *testing.T) {
	if _, err := Parse("sbx-broker_local-worker_local-550e8400e29b41d4a716446655440000"); err == nil {
		t.Fatal("expected malformed error for non-canonical uuid")
	}
}

func TestValidateComponentIDRejectsHyphen(t *testing.T) {
	if err := ValidateComponentID("worker-local"); err == nil {
		t.Fatal("expected validation error for hyphenated id")
	}
}

func TestNewFromLocalVMID(t *testing.T) {
	id, err := NewFromLocalVMID("broker_local", "worker_local", "550e8400-e29b-41d4-a716-446655440000")
	if err != nil {
		t.Fatalf("NewFromLocalVMID() unexpected error: %v", err)
	}
	if id != "sbx-broker_local-worker_local-550e8400-e29b-41d4-a716-446655440000" {
		t.Fatalf("unexpected id: %s", id)
	}
}
