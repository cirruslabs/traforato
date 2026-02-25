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
