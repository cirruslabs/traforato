package worker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/fedor/traforato/internal/auth"
)

func (s *Service) handleProxy(w http.ResponseWriter, r *http.Request, principal auth.Principal, sandboxID string, parts []string) {
	if len(parts) < 4 {
		s.writeError(w, http.StatusNotFound, "route not found")
		return
	}
	if _, err := s.getOwnedSandbox(principal, sandboxID); err != nil {
		s.writeOwnedError(w, err)
		return
	}

	port, err := parsePort(parts[3])
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid port")
		return
	}

	upstreamPath := "/"
	if len(parts) > 4 {
		upstreamPath = "/" + strings.Join(parts[4:], "/")
		if strings.HasSuffix(r.URL.Path, "/") {
			upstreamPath += "/"
		}
	}

	target := &url.URL{Scheme: "http", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(port))}
	proxy := httputil.NewSingleHostReverseProxy(target)
	baseDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		baseDirector(req)
		req.URL.Path = upstreamPath
		req.URL.RawPath = upstreamPath
		req.Host = target.Host
		req.Header.Set("X-Traforato-Sandbox-Id", sandboxID)
		req.Header.Set("X-Forwarded-Proto", requestProto(r))
		req.Header.Set("X-Forwarded-Host", requestHost(r))
		req.Header.Set("X-Forwarded-Port", requestPort(r))
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = 30 * time.Second
	proxy.Transport = transport
	proxy.ErrorHandler = func(rw http.ResponseWriter, _ *http.Request, proxyErr error) {
		status := http.StatusBadGateway
		message := "upstream not reachable"
		var netErr net.Error
		if errors.Is(proxyErr, context.DeadlineExceeded) || (errors.As(proxyErr, &netErr) && netErr.Timeout()) {
			status = http.StatusGatewayTimeout
			message = "upstream timeout"
		}
		s.writeError(rw, status, message)
	}

	proxy.ServeHTTP(w, r)
}

func (s *Service) handleGetPortURL(w http.ResponseWriter, r *http.Request, principal auth.Principal, sandboxID, portPart string) {
	if _, err := s.getOwnedSandbox(principal, sandboxID); err != nil {
		s.writeOwnedError(w, err)
		return
	}

	port, err := parsePort(portPart)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid port")
		return
	}
	protocol := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("protocol")))
	if protocol == "" {
		protocol = "https"
	}
	switch protocol {
	case "http", "https", "ws", "wss":
	default:
		s.writeError(w, http.StatusBadRequest, "protocol must be one of: http, https, ws, wss")
		return
	}

	host := requestHost(r)
	if host == "" {
		host = "localhost"
	}
	discoveredURL := fmt.Sprintf("%s://%s/sandboxes/%s/proxy/%d", protocol, host, sandboxID, port)
	s.writeJSON(w, http.StatusOK, map[string]any{
		"sandbox_id": sandboxID,
		"port":       port,
		"protocol":   protocol,
		"url":        discoveredURL,
	})
}

func parsePort(raw string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || port <= 0 || port > 65535 {
		return 0, errors.New("invalid port")
	}
	return port, nil
}

func requestProto(r *http.Request) string {
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		return strings.TrimSpace(parts[0])
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func requestHost(r *http.Request) string {
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		return strings.TrimSpace(parts[0])
	}
	return r.Host
}

func requestPort(r *http.Request) string {
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-Port")); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		return strings.TrimSpace(parts[0])
	}
	host := requestHost(r)
	if _, port, err := net.SplitHostPort(host); err == nil {
		return port
	}
	if requestProto(r) == "https" || requestProto(r) == "wss" {
		return "443"
	}
	return "80"
}
