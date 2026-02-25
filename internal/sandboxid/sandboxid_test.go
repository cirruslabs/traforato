package sandboxid

import (
	"strings"
	"testing"
)

func TestWorkerHashIsCaseInsensitive(t *testing.T) {
	a := WorkerHash("Worker-A")
	b := WorkerHash("worker-a")
	if a != b {
		t.Fatalf("expected same hash, got %q != %q", a, b)
	}
}

func TestParseValidID(t *testing.T) {
	id := "sbx_7f4ecf5b88c924f2c7f9f1e6ee629d8f_01HZYXW2A3BCDEF4GHJKMNPQRS"
	parsed, err := Parse(id)
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if parsed.WorkerHash != "7f4ecf5b88c924f2c7f9f1e6ee629d8f" {
		t.Fatalf("unexpected worker hash: %s", parsed.WorkerHash)
	}
}

func TestNewAndParseRoundtrip(t *testing.T) {
	id, err := New("worker-a.local", strings.NewReader(strings.Repeat("x", 32)))
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}
	parsed, err := Parse(id)
	if err != nil {
		t.Fatalf("Parse() unexpected error: %v", err)
	}
	if parsed.WorkerHash != WorkerHash("worker-a.local") {
		t.Fatalf("expected worker hash %s, got %s", WorkerHash("worker-a.local"), parsed.WorkerHash)
	}
}

func TestParseRejectsMalformedID(t *testing.T) {
	if _, err := Parse("sbx_invalid"); err == nil {
		t.Fatal("expected malformed error")
	}
}
