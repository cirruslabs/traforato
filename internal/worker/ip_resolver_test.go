package worker

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseResolvedIPPlainAndJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		output string
		want   netip.Addr
	}{
		{
			name:   "plain output",
			output: "192.168.64.12\n",
			want:   netip.MustParseAddr("192.168.64.12"),
		},
		{
			name:   "json output",
			output: `{"ip":"10.20.30.40"}`,
			want:   netip.MustParseAddr("10.20.30.40"),
		},
		{
			name:   "json nested output",
			output: `{"vm":{"network":{"ip":"172.16.0.5"}}}`,
			want:   netip.MustParseAddr("172.16.0.5"),
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseResolvedIP([]byte(tc.output))
			if err != nil {
				t.Fatalf("parseResolvedIP() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("parseResolvedIP() = %s want %s", got, tc.want)
			}
		})
	}
}

func TestParseResolvedIPRejectsMalformedOutput(t *testing.T) {
	t.Parallel()

	_, err := parseResolvedIP([]byte("no ip here"))
	if !errors.Is(err, ErrInvalidResolvedIP) {
		t.Fatalf("expected ErrInvalidResolvedIP, got %v", err)
	}
}

func TestCommandIPResolverResolveTartAndVetu(t *testing.T) {
	t.Parallel()

	tartScript := writeScript(t, "tart-ip.sh", "#!/bin/sh\necho 192.168.64.20\n")
	vetuScript := writeScript(t, "vetu-ip.sh", "#!/bin/sh\necho '{\"ip\":\"10.42.0.9\"}'\n")
	resolver := CommandIPResolver{
		TartBin: tartScript,
		VetuBin: vetuScript,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	tartIP, err := resolver.Resolve(ctx, "tart", "550e8400-e29b-41d4-a716-446655440000")
	if err != nil {
		t.Fatalf("Resolve(tart) error = %v", err)
	}
	if tartIP.String() != "192.168.64.20" {
		t.Fatalf("unexpected tart IP: %s", tartIP)
	}

	vetuIP, err := resolver.Resolve(ctx, "vetu", "550e8400-e29b-41d4-a716-446655440001")
	if err != nil {
		t.Fatalf("Resolve(vetu) error = %v", err)
	}
	if vetuIP.String() != "10.42.0.9" {
		t.Fatalf("unexpected vetu IP: %s", vetuIP)
	}
}

func TestCommandIPResolverResolveRejectsUnsupportedVirtualization(t *testing.T) {
	t.Parallel()

	resolver := CommandIPResolver{}
	_, err := resolver.Resolve(context.Background(), "unknown", "550e8400-e29b-41d4-a716-446655440000")
	if !errors.Is(err, ErrUnsupportedVirtualization) {
		t.Fatalf("expected ErrUnsupportedVirtualization, got %v", err)
	}
}

func TestCommandIPResolverResolveCommandFailure(t *testing.T) {
	t.Parallel()

	badScript := writeScript(t, "bad-vetu.sh", "#!/bin/sh\necho boom >&2\nexit 1\n")
	resolver := CommandIPResolver{VetuBin: badScript}

	_, err := resolver.Resolve(context.Background(), "vetu", "550e8400-e29b-41d4-a716-446655440000")
	if !errors.Is(err, ErrResolveCommandFailed) {
		t.Fatalf("expected ErrResolveCommandFailed, got %v", err)
	}
}

func writeScript(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
	return path
}
