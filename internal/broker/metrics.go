package broker

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

type sandboxKindCount struct {
	Virtualization string
	Image          string
	CPU            int
	Available      int
}

type sandboxMetricsSnapshot struct {
	GeneratedAt time.Time
	BrokerID    string

	WorkersRegisteredTotal  int
	WorkersActiveTotal      int
	WorkersUnavailableTotal int
	WorkersStaticTotal      int
	WorkersDynamicTotal     int

	AvailableSandboxesTotal    int
	AvailableSandboxKindsTotal int
	Kinds                      []sandboxKindCount
}

type sandboxKindKey struct {
	Virtualization string
	Image          string
	CPU            int
}

func (s *Service) handleSandboxMetrics(w http.ResponseWriter) {
	snapshot := s.snapshotSandboxMetrics()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, renderSandboxMetrics(snapshot))
}

func (s *Service) snapshotSandboxMetrics() sandboxMetricsSnapshot {
	now := s.cfg.Clock().UTC()
	snapshot := sandboxMetricsSnapshot{
		GeneratedAt: now,
		BrokerID:    s.cfg.BrokerID,
	}

	kindCounts := make(map[sandboxKindKey]int)

	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, worker := range s.workersByID {
		snapshot.WorkersRegisteredTotal++
		if worker.Static {
			snapshot.WorkersStaticTotal++
		} else {
			snapshot.WorkersDynamicTotal++
		}
		if s.workerIsActiveAt(worker, now) {
			snapshot.WorkersActiveTotal++
		}
	}
	snapshot.WorkersUnavailableTotal = snapshot.WorkersRegisteredTotal - snapshot.WorkersActiveTotal

	for _, meta := range s.vmByHash {
		worker, ok := s.workersByID[meta.WorkerID]
		if !ok || !s.workerIsActiveAt(worker, now) {
			continue
		}
		key := sandboxKindKey{
			Virtualization: meta.Virtualization,
			Image:          meta.Image,
			CPU:            meta.CPU,
		}
		kindCounts[key]++
		snapshot.AvailableSandboxesTotal++
	}

	snapshot.AvailableSandboxKindsTotal = len(kindCounts)
	snapshot.Kinds = make([]sandboxKindCount, 0, len(kindCounts))
	for key, count := range kindCounts {
		snapshot.Kinds = append(snapshot.Kinds, sandboxKindCount{
			Virtualization: key.Virtualization,
			Image:          key.Image,
			CPU:            key.CPU,
			Available:      count,
		})
	}
	sort.Slice(snapshot.Kinds, func(i, j int) bool {
		left := snapshot.Kinds[i]
		right := snapshot.Kinds[j]
		if left.Virtualization != right.Virtualization {
			return left.Virtualization < right.Virtualization
		}
		if left.Image != right.Image {
			return left.Image < right.Image
		}
		return left.CPU < right.CPU
	})

	return snapshot
}

func renderSandboxMetrics(snapshot sandboxMetricsSnapshot) string {
	var b strings.Builder

	b.WriteString("# traforato broker sandbox availability\n")
	b.WriteString("generated_at=")
	b.WriteString(snapshot.GeneratedAt.UTC().Format(time.RFC3339))
	b.WriteByte('\n')
	b.WriteString("broker_id=")
	b.WriteString(snapshot.BrokerID)
	b.WriteByte('\n')
	b.WriteString("workers_registered_total=")
	b.WriteString(strconv.Itoa(snapshot.WorkersRegisteredTotal))
	b.WriteByte('\n')
	b.WriteString("workers_active_total=")
	b.WriteString(strconv.Itoa(snapshot.WorkersActiveTotal))
	b.WriteByte('\n')
	b.WriteString("workers_unavailable_total=")
	b.WriteString(strconv.Itoa(snapshot.WorkersUnavailableTotal))
	b.WriteByte('\n')
	b.WriteString("workers_static_total=")
	b.WriteString(strconv.Itoa(snapshot.WorkersStaticTotal))
	b.WriteByte('\n')
	b.WriteString("workers_dynamic_total=")
	b.WriteString(strconv.Itoa(snapshot.WorkersDynamicTotal))
	b.WriteByte('\n')
	b.WriteString("available_sandboxes_total=")
	b.WriteString(strconv.Itoa(snapshot.AvailableSandboxesTotal))
	b.WriteByte('\n')
	b.WriteString("available_sandbox_kinds_total=")
	b.WriteString(strconv.Itoa(snapshot.AvailableSandboxKindsTotal))
	b.WriteString("\n\n")

	b.WriteString("virtualization\timage\tcpu\tavailable\n")
	for _, kind := range snapshot.Kinds {
		_, _ = fmt.Fprintf(&b, "%s\t%s\t%d\t%d\n", kind.Virtualization, kind.Image, kind.CPU, kind.Available)
	}

	return b.String()
}
