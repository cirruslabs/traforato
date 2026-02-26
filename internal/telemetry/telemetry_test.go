package telemetry

import (
	"context"
	"errors"
	"testing"

	"github.com/fedor/traforato/internal/auth"
)

func TestAuthModeGauge(t *testing.T) {
	prod := NewRecorder(auth.ModeProd)
	t.Cleanup(func() { _ = prod.Shutdown(context.Background()) })
	if got := prod.GaugeValue(MetricServiceAuthMode); got != 1 {
		t.Fatalf("expected prod gauge 1, got %v", got)
	}

	dev := NewRecorder(auth.ModeDev)
	t.Cleanup(func() { _ = dev.Shutdown(context.Background()) })
	if got := dev.GaugeValue(MetricServiceAuthMode); got != 0 {
		t.Fatalf("expected dev gauge 0, got %v", got)
	}
}

func TestMetricLabelLintRejectsHighCardinalityKeys(t *testing.T) {
	if err := ValidateLabels(map[string]string{"sandbox_id": "sbx-..."}); !errors.Is(err, ErrHighCardinalityLabel) {
		t.Fatalf("expected high-cardinality rejection, got %v", err)
	}
	if err := ValidateLabels(map[string]string{"status_code": "200", "worker_id": "worker-a"}); err != nil {
		t.Fatalf("expected valid labels, got %v", err)
	}
	if err := ValidateLabels(map[string]string{"custom": "value"}); !errors.Is(err, ErrHighCardinalityLabel) {
		t.Fatalf("expected rejection for unknown label key, got %v", err)
	}
}
