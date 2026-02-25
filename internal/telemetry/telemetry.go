package telemetry

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/fedor/traforato/internal/auth"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

const (
	MetricWorkerCPUTotal            = "worker.cpu.total_cores"
	MetricWorkerCPUAllocated        = "worker.cpu.allocated_cores"
	MetricWorkerMemoryTotal         = "worker.memory.total_mib"
	MetricWorkerMemoryAllocated     = "worker.memory.allocated_mib"
	MetricWorkerSandboxesLive       = "worker.sandboxes.live"
	MetricWorkerWarmReady           = "worker.sandboxes.warm.ready"
	MetricWorkerWarmTarget          = "worker.sandboxes.warm.target"
	MetricWorkerWarmDeficit         = "worker.sandboxes.warm.deficit"
	MetricWorkerReadyDuration       = "worker.sandbox.ready.duration_seconds"
	MetricWorkerFirstExecTTI        = "worker.sandbox.first_exec.tti_seconds"
	MetricWorkerExecStartDuration   = "worker.exec.start.duration_seconds"
	MetricWorkerExecDuration        = "worker.exec.duration_seconds"
	MetricBrokerPlacementDur        = "broker.placement.duration_seconds"
	MetricBrokerNoCapacityTotal     = "broker.no_capacity.total"
	MetricWorkerWarmupFailuresTotal = "worker.warmup.failures.total"
	MetricWorkerSSHReconnectsTotal  = "worker.ssh.reconnects.total"
	MetricWorkerWarmHitTotal        = "worker.warm.hit.total"
	MetricWorkerWarmMissTotal       = "worker.warm.miss.total"
	MetricWorkerAuthFailuresTotal   = "worker.auth.failures.total"
	MetricServiceAuthMode           = "service.auth.mode"
)

var (
	ErrHighCardinalityLabel = errors.New("high-cardinality label rejected")

	allowedLabels = []string{
		"worker_id",
		"virtualization",
		"cpu",
		"start_type",
		"result",
		"status_code",
		"reason",
		"image_family",
	}
	disallowedLabels = []string{"sandbox_id", "exec_id", "client_id", "image", "full_image"}
)

type MetricSample struct {
	Name   string
	Value  float64
	Labels map[string]string
}

type Recorder struct {
	mu       sync.Mutex
	mode     auth.Mode
	counters map[string]float64
	gauges   map[string]float64
	history  []MetricSample

	propagator propagation.TextMapPropagator
	tracer     trace.Tracer
	tp         *sdktrace.TracerProvider
}

func NewRecorder(mode auth.Mode) *Recorder {
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(0.10))),
	)
	rec := &Recorder{
		mode:       mode,
		counters:   make(map[string]float64),
		gauges:     make(map[string]float64),
		propagator: propagation.TraceContext{},
		tracer:     tp.Tracer("traforato"),
		tp:         tp,
	}
	authMode := 0.0
	if mode == auth.ModeProd {
		authMode = 1
	}
	rec.gauges[MetricServiceAuthMode] = authMode
	return rec
}

func (r *Recorder) Shutdown(ctx context.Context) error {
	if r.tp == nil {
		return nil
	}
	return r.tp.Shutdown(ctx)
}

func (r *Recorder) StartSpan(ctx context.Context, name string) (context.Context, trace.Span) {
	return r.tracer.Start(ctx, name)
}

func (r *Recorder) Extract(ctx context.Context, header http.Header) context.Context {
	return r.propagator.Extract(ctx, propagation.HeaderCarrier(header))
}

func (r *Recorder) Inject(ctx context.Context, header http.Header) {
	r.propagator.Inject(ctx, propagation.HeaderCarrier(header))
}

func (r *Recorder) Inc(name string, labels map[string]string) error {
	if err := ValidateLabels(labels); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.counters[name] += 1
	r.history = append(r.history, MetricSample{Name: name, Value: 1, Labels: copyLabels(labels)})
	return nil
}

func (r *Recorder) Observe(name string, value float64, labels map[string]string) error {
	if err := ValidateLabels(labels); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.history = append(r.history, MetricSample{Name: name, Value: value, Labels: copyLabels(labels)})
	return nil
}

func (r *Recorder) SetGauge(name string, value float64, labels map[string]string) error {
	if err := ValidateLabels(labels); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gauges[name] = value
	r.history = append(r.history, MetricSample{Name: name, Value: value, Labels: copyLabels(labels)})
	return nil
}

func (r *Recorder) CounterValue(name string) float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.counters[name]
}

func (r *Recorder) GaugeValue(name string) float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.gauges[name]
}

func (r *Recorder) Samples() []MetricSample {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]MetricSample, 0, len(r.history))
	for _, sample := range r.history {
		out = append(out, MetricSample{
			Name:   sample.Name,
			Value:  sample.Value,
			Labels: copyLabels(sample.Labels),
		})
	}
	return out
}

func ValidateLabels(labels map[string]string) error {
	if len(labels) == 0 {
		return nil
	}
	for key := range labels {
		if slices.Contains(disallowedLabels, key) {
			return fmt.Errorf("%w: key=%s", ErrHighCardinalityLabel, key)
		}
		if !slices.Contains(allowedLabels, key) {
			return fmt.Errorf("%w: key=%s", ErrHighCardinalityLabel, key)
		}
	}
	return nil
}

func copyLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	out := make(map[string]string, len(labels))
	for k, v := range labels {
		out[k] = v
	}
	return out
}

func SpanIDs(ctx context.Context) (traceID, spanID string) {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return "", ""
	}
	return sc.TraceID().String(), sc.SpanID().String()
}

func DurationSeconds(start time.Time) float64 {
	return time.Since(start).Seconds()
}
