package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

var (
	ErrUnsupportedVirtualization = errors.New("unsupported virtualization")
	ErrResolveCommandFailed      = errors.New("ip resolve command failed")
	ErrInvalidResolvedIP         = errors.New("invalid resolved ip")
)

// IPResolver resolves a sandbox VM IP from virtualization runtime metadata.
type IPResolver interface {
	Resolve(ctx context.Context, virtualization, vmID string) (netip.Addr, error)
}

type CommandIPResolver struct {
	TartBin string
	VetuBin string
}

func (r CommandIPResolver) Resolve(ctx context.Context, virtualization, vmID string) (netip.Addr, error) {
	virtualization = strings.ToLower(strings.TrimSpace(virtualization))
	if virtualization == "" {
		virtualization = "vetu"
	}
	vmID = strings.TrimSpace(vmID)
	if vmID == "" {
		return netip.Addr{}, fmt.Errorf("%w: vm id is required", ErrInvalidResolvedIP)
	}

	switch virtualization {
	case "tart":
		bin := strings.TrimSpace(r.TartBin)
		if bin == "" {
			bin = "tart"
		}
		return resolveWithBinary(ctx, bin, vmID)
	case "vetu":
		bin := strings.TrimSpace(r.VetuBin)
		if bin == "" {
			bin = "vetu"
		}
		return resolveWithBinary(ctx, bin, vmID)
	default:
		return netip.Addr{}, fmt.Errorf("%w: %s", ErrUnsupportedVirtualization, virtualization)
	}
}

func resolveWithBinary(ctx context.Context, bin, vmID string) (netip.Addr, error) {
	// #nosec G204 -- binary path is controlled by trusted service configuration.
	cmd := exec.CommandContext(ctx, bin, "ip", vmID)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%w: %v (output=%s)", ErrResolveCommandFailed, err, strings.TrimSpace(string(output)))
	}
	addr, err := parseResolvedIP(output)
	if err != nil {
		return netip.Addr{}, err
	}
	return addr, nil
}

func parseResolvedIP(output []byte) (netip.Addr, error) {
	trimmed := strings.TrimSpace(string(output))
	if trimmed == "" {
		return netip.Addr{}, fmt.Errorf("%w: empty output", ErrInvalidResolvedIP)
	}

	if ip := findIPInText(trimmed); ip != "" {
		addr, err := netip.ParseAddr(ip)
		if err == nil {
			return addr.Unmap(), nil
		}
	}

	var decoded any
	if err := json.Unmarshal(output, &decoded); err == nil {
		if ip, ok := findIPInJSON(decoded); ok {
			addr, err := netip.ParseAddr(ip)
			if err == nil {
				return addr.Unmap(), nil
			}
		}
	}

	return netip.Addr{}, fmt.Errorf("%w: output=%q", ErrInvalidResolvedIP, trimmed)
}

func findIPInJSON(v any) (string, bool) {
	switch typed := v.(type) {
	case map[string]any:
		for key, value := range typed {
			if strings.EqualFold(strings.TrimSpace(key), "ip") {
				if raw, ok := value.(string); ok {
					candidate := strings.TrimSpace(raw)
					if candidate != "" {
						return candidate, true
					}
				}
			}
			if ip, ok := findIPInJSON(value); ok {
				return ip, true
			}
		}
	case []any:
		for _, value := range typed {
			if ip, ok := findIPInJSON(value); ok {
				return ip, true
			}
		}
	}
	return "", false
}

func findIPInText(raw string) string {
	lines := strings.Split(raw, "\n")
	for _, line := range lines {
		for _, token := range strings.Fields(line) {
			candidate := strings.Trim(token, " \t\r\n\"'`,;[]{}()")
			if candidate == "" {
				continue
			}
			if _, err := netip.ParseAddr(candidate); err == nil {
				return candidate
			}
		}
	}
	return ""
}
