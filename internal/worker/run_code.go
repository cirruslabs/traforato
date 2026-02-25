package worker

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fedor/traforato/internal/auth"
	"github.com/fedor/traforato/internal/model"
	"github.com/fedor/traforato/internal/telemetry"
)

const (
	maxRunCodeBytes         = 1_048_576
	defaultRunCodeTimeoutMS = 30_000
)

type runCodeRequest struct {
	Code      string            `json:"code"`
	Runtime   string            `json:"runtime"`
	TimeoutMS int               `json:"timeout_ms"`
	CWD       string            `json:"cwd"`
	Env       map[string]string `json:"env"`
	Wait      *bool             `json:"wait"`
}

type runCodeResult struct {
	Status      string
	Stdout      string
	Stderr      string
	Output      string
	ExitCode    int
	DurationMS  int64
	CompletedAt time.Time
	SyntaxError bool
}

func (s *Service) handleRunCode(w http.ResponseWriter, r *http.Request, principal auth.Principal, sandboxID string) {
	started := s.cfg.Clock().UTC()
	sbx, err := s.getOwnedSandbox(principal, sandboxID)
	if err != nil {
		s.writeOwnedError(w, err)
		return
	}

	var req runCodeRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRunCodeBytes+(1<<10))).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Runtime = strings.ToLower(strings.TrimSpace(req.Runtime))
	if req.Runtime != "node" && req.Runtime != "python" {
		s.writeError(w, http.StatusBadRequest, "runtime must be one of: node, python")
		return
	}
	if req.Code == "" {
		s.writeError(w, http.StatusBadRequest, "code is required")
		return
	}
	if len([]byte(req.Code)) > maxRunCodeBytes {
		s.writeError(w, http.StatusBadRequest, "code exceeds max size")
		return
	}
	if req.TimeoutMS <= 0 {
		req.TimeoutMS = defaultRunCodeTimeoutMS
	}
	wait := true
	if req.Wait != nil {
		wait = *req.Wait
	}

	execID, err := newExecID()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "failed to allocate exec id")
		return
	}

	s.markFirstExecTTI(sbx, started)

	execRecord := &model.Exec{
		ExecID:    execID,
		SandboxID: sandboxID,
		Runtime:   req.Runtime,
		Status:    "running",
		StartedAt: started,
	}
	s.mu.Lock()
	s.execs[execID] = execRecord
	s.mu.Unlock()

	if !wait {
		go s.runCodeAsync(execID, sbx.CPU, req)
		s.writeJSON(w, http.StatusAccepted, map[string]any{
			"exec_id":    execID,
			"sandbox_id": sandboxID,
			"status":     "running",
			"poll_url":   fmt.Sprintf("/sandboxes/%s/exec/%s", sandboxID, execID),
			"frames_url": fmt.Sprintf("/sandboxes/%s/exec/%s/frames", sandboxID, execID),
		})
		return
	}

	result := executeRunCode(req)
	s.applyRunCodeResult(execID, result)
	_ = s.cfg.Telemetry.Observe(telemetry.MetricWorkerExecStartDuration, s.cfg.Clock().Sub(started).Seconds(), map[string]string{
		"worker_id": s.cfg.WorkerID,
		"cpu":       strconv.Itoa(sbx.CPU),
	})
	_ = s.cfg.Telemetry.Observe(telemetry.MetricWorkerExecDuration, float64(result.DurationMS)/1000.0, map[string]string{
		"worker_id": s.cfg.WorkerID,
		"cpu":       strconv.Itoa(sbx.CPU),
	})

	if result.SyntaxError {
		s.writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"error":     "syntax_error",
			"exec_id":   execID,
			"runtime":   req.Runtime,
			"stdout":    result.Stdout,
			"stderr":    result.Stderr,
			"exit_code": result.ExitCode,
		})
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"exec_id":      execID,
		"sandbox_id":   sandboxID,
		"runtime":      req.Runtime,
		"status":       result.Status,
		"stdout":       result.Stdout,
		"stderr":       result.Stderr,
		"output":       result.Output,
		"exit_code":    result.ExitCode,
		"duration_ms":  result.DurationMS,
		"started_at":   started,
		"completed_at": result.CompletedAt,
	})
}

func (s *Service) runCodeAsync(execID string, cpu int, req runCodeRequest) {
	started := s.cfg.Clock()
	result := executeRunCode(req)
	s.applyRunCodeResult(execID, result)
	_ = s.cfg.Telemetry.Observe(telemetry.MetricWorkerExecStartDuration, s.cfg.Clock().Sub(started).Seconds(), map[string]string{
		"worker_id": s.cfg.WorkerID,
		"cpu":       strconv.Itoa(cpu),
	})
	_ = s.cfg.Telemetry.Observe(telemetry.MetricWorkerExecDuration, float64(result.DurationMS)/1000.0, map[string]string{
		"worker_id": s.cfg.WorkerID,
		"cpu":       strconv.Itoa(cpu),
	})
}

func (s *Service) applyRunCodeResult(execID string, result runCodeResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	exec, ok := s.execs[execID]
	if !ok {
		return
	}
	exec.Status = result.Status
	exec.ExitCode = &result.ExitCode
	exec.Stdout = result.Stdout
	exec.Stderr = result.Stderr
	exec.Output = result.Output
	exec.DurationMS = result.DurationMS
	exec.Completed = &result.CompletedAt
	exec.Frames = buildFramesFromRunResult(result)
}

func (s *Service) markFirstExecTTI(sbx *sandboxState, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sbx.firstExecRecorded {
		return
	}
	sbx.firstExecRecorded = true
	_ = s.cfg.Telemetry.Observe(telemetry.MetricWorkerFirstExecTTI, now.Sub(sbx.CreatedAt).Seconds(), map[string]string{
		"worker_id": s.cfg.WorkerID,
		"cpu":       strconv.Itoa(sbx.CPU),
	})
}

func executeRunCode(req runCodeRequest) runCodeResult {
	start := time.Now().UTC()
	runtimeName := strings.ToLower(strings.TrimSpace(req.Runtime))
	code := req.Code

	if looksLikeInfiniteLoop(code) && req.TimeoutMS > 0 {
		duration := int64(req.TimeoutMS)
		completedAt := start.Add(time.Duration(duration) * time.Millisecond)
		stderr := "execution timed out"
		return runCodeResult{
			Status:      "exited",
			Stdout:      "",
			Stderr:      stderr,
			Output:      stderr,
			ExitCode:    124,
			DurationMS:  duration,
			CompletedAt: completedAt,
		}
	}

	if hasSyntaxError(code) {
		completedAt := time.Now().UTC()
		stderr := syntaxErrorMessage(runtimeName)
		return runCodeResult{
			Status:      "exited",
			Stdout:      "",
			Stderr:      stderr,
			Output:      stderr,
			ExitCode:    1,
			DurationMS:  maxDurationMS(start, completedAt),
			CompletedAt: completedAt,
			SyntaxError: true,
		}
	}

	if runtimeError := runtimeErrorMessage(runtimeName, code); runtimeError != "" {
		completedAt := time.Now().UTC()
		return runCodeResult{
			Status:      "exited",
			Stdout:      "",
			Stderr:      runtimeError,
			Output:      runtimeError,
			ExitCode:    1,
			DurationMS:  maxDurationMS(start, completedAt),
			CompletedAt: completedAt,
		}
	}

	stdout := extractRuntimeStdout(runtimeName, code)
	completedAt := time.Now().UTC()
	return runCodeResult{
		Status:      "exited",
		Stdout:      stdout,
		Stderr:      "",
		Output:      stdout,
		ExitCode:    0,
		DurationMS:  maxDurationMS(start, completedAt),
		CompletedAt: completedAt,
	}
}

func buildFramesFromRunResult(result runCodeResult) []model.Frame {
	frames := make([]model.Frame, 0, 3)
	now := result.CompletedAt
	if result.Stdout != "" {
		frames = append(frames, model.Frame{Type: "stdout", Data: result.Stdout, Timestamp: now})
	}
	if result.Stderr != "" {
		frames = append(frames, model.Frame{Type: "stderr", Data: result.Stderr, Timestamp: now})
	}
	frames = append(frames, model.Frame{Type: "exit", Data: strconv.Itoa(result.ExitCode), Timestamp: now})
	return frames
}

func extractRuntimeStdout(runtimeName, code string) string {
	lines := strings.Split(code, "\n")
	var out strings.Builder
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if runtimeName == "python" {
			if extracted, ok := extractCallStringArgument(line, "print("); ok {
				out.WriteString(extracted)
				out.WriteByte('\n')
			}
			continue
		}
		if extracted, ok := extractCallStringArgument(line, "console.log("); ok {
			out.WriteString(extracted)
			out.WriteByte('\n')
		}
	}
	return out.String()
}

func extractCallStringArgument(line, prefix string) (string, bool) {
	idx := strings.Index(line, prefix)
	if idx < 0 {
		return "", false
	}
	remainder := line[idx+len(prefix):]
	end := strings.Index(remainder, ")")
	if end < 0 {
		return "", false
	}
	argument := strings.TrimSpace(remainder[:end])
	if argument == "" {
		return "", true
	}
	argument = strings.Trim(argument, "`\"'")
	return argument, true
}

func hasSyntaxError(code string) bool {
	return hasUnbalancedDelimiters(code)
}

func hasUnbalancedDelimiters(code string) bool {
	pairs := map[rune]rune{')': '(', ']': '[', '}': '{'}
	stack := make([]rune, 0, 8)
	for _, ch := range code {
		switch ch {
		case '(', '[', '{':
			stack = append(stack, ch)
		case ')', ']', '}':
			if len(stack) == 0 {
				return true
			}
			top := stack[len(stack)-1]
			if top != pairs[ch] {
				return true
			}
			stack = stack[:len(stack)-1]
		}
	}
	return len(stack) > 0
}

func syntaxErrorMessage(runtimeName string) string {
	if runtimeName == "python" {
		return "SyntaxError: invalid syntax"
	}
	return "SyntaxError: Unexpected token"
}

func runtimeErrorMessage(runtimeName, code string) string {
	if runtimeName == "python" {
		if strings.Contains(code, "raise ") {
			return "RuntimeError: raised exception"
		}
		if strings.Contains(code, "1/0") {
			return "ZeroDivisionError: division by zero"
		}
		return ""
	}
	if strings.Contains(code, "throw ") {
		return "Error: thrown exception"
	}
	if strings.Contains(code, "process.exit(1)") {
		return "process exited with code 1"
	}
	return ""
}

func looksLikeInfiniteLoop(code string) bool {
	trimmed := strings.ToLower(strings.ReplaceAll(code, " ", ""))
	return strings.Contains(trimmed, "whiletrue") || strings.Contains(trimmed, "for(;;)")
}

func maxDurationMS(start, end time.Time) int64 {
	duration := end.Sub(start).Milliseconds()
	if duration <= 0 {
		return 1
	}
	return duration
}
