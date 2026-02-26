package model

import "time"

type Sandbox struct {
	SandboxID      string    `json:"sandbox_id"`
	OwnerClientID  string    `json:"-"`
	Image          string    `json:"image"`
	CPU            int       `json:"cpu"`
	MemoryMiB      int       `json:"memory_mib"`
	Virtualization string    `json:"virtualization"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type CreateSandboxRequest struct {
	Image          string `json:"image"`
	CPU            int    `json:"cpu"`
	Virtualization string `json:"virtualization"`
	HardwareSKU    string `json:"hardware_sku,omitempty"`
	TTLSeconds     int    `json:"ttl_seconds"`
}

const (
	VirtualizationVetu = "vetu"
	VirtualizationTart = "tart"

	DefaultTartImage = "ghcr.io/cirruslabs/macos-tahoe-base:latest"
)

// ApplyCreateSandboxDefaults mutates req with platform defaults.
func ApplyCreateSandboxDefaults(req *CreateSandboxRequest) {
	if req.Virtualization == "" {
		req.Virtualization = VirtualizationVetu
	}
	if req.CPU <= 0 {
		req.CPU = 1
	}
	if req.Image == "" && req.Virtualization == VirtualizationTart {
		req.Image = DefaultTartImage
	}
}

const (
	WorkerVMEventReady   = "ready"
	WorkerVMEventClaimed = "claimed"
	WorkerVMEventRetired = "retired"
)

// Exec status values.
const (
	ExecStatusRunning = "running"
	ExecStatusExited  = "exited"
)

// Sandbox start type values.
const (
	StartTypeCold = "cold"
	StartTypeWarm = "warm"
)

// Frame type values.
const (
	FrameTypeStdout = "stdout"
	FrameTypeStderr = "stderr"
	FrameTypeExit   = "exit"
)

type WorkerVMEvent struct {
	Event          string    `json:"event"`
	LocalVMID      string    `json:"local_vm_id"`
	Virtualization string    `json:"virtualization"`
	Image          string    `json:"image"`
	CPU            int       `json:"cpu"`
	Timestamp      time.Time `json:"timestamp"`
}

type WorkerRegistrationRequest struct {
	Hostname         string `json:"hostname"`
	BaseURL          string `json:"base_url"`
	HardwareSKU      string `json:"hardware_sku,omitempty"`
	TotalCores       int    `json:"total_cores,omitempty"`
	TotalMemoryMiB   int    `json:"total_memory_mib,omitempty"`
	MaxLiveSandboxes int    `json:"max_live_sandboxes,omitempty"`
}

type WorkerRegistrationResponse struct {
	WorkerID                 string    `json:"worker_id"`
	LeaseTTLSeconds          int       `json:"lease_ttl_seconds"`
	HeartbeatIntervalSeconds int       `json:"heartbeat_interval_seconds"`
	ExpiresAt                time.Time `json:"expires_at"`
}

type Exec struct {
	ExecID     string     `json:"exec_id"`
	SandboxID  string     `json:"sandbox_id"`
	Runtime    string     `json:"runtime,omitempty"`
	Status     string     `json:"status"`
	ExitCode   *int       `json:"exit_code,omitempty"`
	Command    string     `json:"command,omitempty"`
	Stdout     string     `json:"stdout,omitempty"`
	Stderr     string     `json:"stderr,omitempty"`
	Output     string     `json:"output,omitempty"`
	DurationMS int64      `json:"duration_ms,omitempty"`
	StartedAt  time.Time  `json:"started_at"`
	Completed  *time.Time `json:"completed_at,omitempty"`
	StartType  string     `json:"start_type,omitempty"`
	Frames     []Frame    `json:"-"`
	HasTTYTime bool       `json:"-"`
}

type Frame struct {
	Type      string    `json:"type"`
	Data      string    `json:"data,omitempty"`
	Timestamp time.Time `json:"ts"`
}
