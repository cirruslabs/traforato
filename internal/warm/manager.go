package warm

import (
	"errors"
	"math"
	"sort"
	"sync"
	"time"
)

const (
	demandWindow    = 60 * time.Minute
	demandHalfLife  = 20 * time.Minute
	defaultWarmupTO = 2 * time.Minute
)

type Tuple struct {
	Virtualization string
	Image          string
	CPU            int
}

type DemandEvent struct {
	Tuple     Tuple
	Timestamp time.Time
}

type WarmupConfig struct {
	Script  string
	Timeout time.Duration
}

type Runner interface {
	Provision(tuple Tuple) error
	Connect(tuple Tuple) error
	Warmup(tuple Tuple, script string, timeout time.Duration) error
	Reconnect(tuple Tuple) error
}

type Manager struct {
	mu sync.Mutex

	nowFn   func() time.Time
	runner  Runner
	events  []DemandEvent
	targets map[Tuple]int
	ready   map[Tuple]int
	configs map[Tuple]WarmupConfig
}

func NewManager(nowFn func() time.Time, runner Runner) *Manager {
	if nowFn == nil {
		nowFn = time.Now
	}
	return &Manager{
		nowFn:   nowFn,
		runner:  runner,
		targets: make(map[Tuple]int),
		ready:   make(map[Tuple]int),
		configs: make(map[Tuple]WarmupConfig),
	}
}

func (m *Manager) SetTupleConfig(tuple Tuple, targetCount int, script string, timeoutSeconds int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if timeoutSeconds <= 0 {
		timeoutSeconds = int(defaultWarmupTO.Seconds())
	}
	m.targets[tuple] = targetCount
	m.configs[tuple] = WarmupConfig{
		Script:  script,
		Timeout: time.Duration(timeoutSeconds) * time.Second,
	}
}

func (m *Manager) RecordDemand(tuple Tuple) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, DemandEvent{
		Tuple:     tuple,
		Timestamp: m.nowFn().UTC(),
	})
}

func (m *Manager) OnWorkerRegister(capacity int) map[Tuple]int {
	return m.recompute(capacity)
}

func (m *Manager) OnSandboxDelete(capacity int) map[Tuple]int {
	return m.recompute(capacity)
}

func (m *Manager) recompute(capacity int) map[Tuple]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	targets := ComputeTargets(m.events, capacity, m.nowFn())
	for tuple, count := range targets {
		m.targets[tuple] = count
	}
	for tuple := range m.targets {
		if _, ok := targets[tuple]; !ok {
			m.targets[tuple] = 0
		}
	}
	out := make(map[Tuple]int, len(m.targets))
	for k, v := range m.targets {
		out[k] = v
	}
	return out
}

func (m *Manager) ConsumeReady(tuple Tuple) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ready[tuple] <= 0 {
		return false
	}
	m.ready[tuple]--
	return true
}

func (m *Manager) TargetCount(tuple Tuple) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.targets[tuple]
}

func (m *Manager) ReadyCount(tuple Tuple) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ready[tuple]
}

func (m *Manager) WarmDeficit(tuple Tuple) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	target := m.targets[tuple]
	ready := m.ready[tuple]
	if target-ready < 0 {
		return 0
	}
	return target - ready
}

// EnsureReady executes the warm readiness flow until target count is met.
func (m *Manager) EnsureReady(tuple Tuple) error {
	m.mu.Lock()
	target := m.targets[tuple]
	ready := m.ready[tuple]
	cfg := m.configs[tuple]
	runner := m.runner
	m.mu.Unlock()

	if target <= ready {
		return nil
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultWarmupTO
	}

	for i := ready; i < target; i++ {
		if runner != nil {
			if err := runner.Provision(tuple); err != nil {
				return err
			}
			if err := runner.Connect(tuple); err != nil {
				return err
			}
			if err := runner.Warmup(tuple, cfg.Script, cfg.Timeout); err != nil {
				return err
			}
			if err := runner.Reconnect(tuple); err != nil {
				return err
			}
		}
		m.mu.Lock()
		m.ready[tuple]++
		m.mu.Unlock()
	}
	return nil
}

// HandleSSHDrop marks tuple unavailable and attempts full rewarm to target.
func (m *Manager) HandleSSHDrop(tuple Tuple) error {
	m.mu.Lock()
	m.ready[tuple] = 0
	m.mu.Unlock()
	return m.EnsureReady(tuple)
}

func ComputeTargets(events []DemandEvent, capacity int, now time.Time) map[Tuple]int {
	targets := make(map[Tuple]int)
	if capacity <= 0 || len(events) == 0 {
		return targets
	}

	weights := make(map[Tuple]float64)
	cutoff := now.Add(-demandWindow)
	for _, event := range events {
		if event.Timestamp.Before(cutoff) {
			continue
		}
		age := now.Sub(event.Timestamp)
		if age < 0 {
			age = 0
		}
		weight := math.Pow(0.5, age.Minutes()/demandHalfLife.Minutes())
		weights[event.Tuple] += weight
	}
	if len(weights) == 0 {
		return targets
	}

	totalWeight := 0.0
	hottestTuple := Tuple{}
	hottestWeight := -1.0
	for tuple, w := range weights {
		totalWeight += w
		if w > hottestWeight {
			hottestWeight = w
			hottestTuple = tuple
		}
	}
	if totalWeight == 0 {
		return targets
	}

	type remainder struct {
		Tuple Tuple
		Frac  float64
	}
	remainders := make([]remainder, 0, len(weights))
	allocated := 0
	for tuple, weight := range weights {
		raw := (weight / totalWeight) * float64(capacity)
		base := int(math.Floor(raw))
		targets[tuple] = base
		allocated += base
		remainders = append(remainders, remainder{
			Tuple: tuple,
			Frac:  raw - float64(base),
		})
	}

	sort.Slice(remainders, func(i, j int) bool {
		return remainders[i].Frac > remainders[j].Frac
	})
	for i := 0; i < capacity-allocated && i < len(remainders); i++ {
		targets[remainders[i].Tuple]++
	}

	if capacity > 0 && targets[hottestTuple] == 0 {
		// Guarantee one warm slot for hottest tuple when any capacity exists.
		targets[hottestTuple] = 1
		// Keep total within capacity by stealing from other tuples with highest counts.
		for sumTargets(targets) > capacity {
			donor, ok := maxTupleExcluding(targets, hottestTuple)
			if !ok {
				break
			}
			targets[donor]--
		}
	}
	return targets
}

func maxTupleExcluding(targets map[Tuple]int, excluded Tuple) (Tuple, bool) {
	bestTuple := Tuple{}
	bestCount := 0
	found := false
	for tuple, count := range targets {
		if tuple == excluded {
			continue
		}
		if count > bestCount {
			bestCount = count
			bestTuple = tuple
			found = true
		}
	}
	return bestTuple, found
}

func sumTargets(targets map[Tuple]int) int {
	sum := 0
	for _, count := range targets {
		sum += count
	}
	return sum
}

var ErrWarmupFailed = errors.New("warmup failed")
