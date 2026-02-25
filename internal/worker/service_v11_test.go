package worker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fedor/traforetto/internal/auth"
)

func createSandboxWithAuth(t *testing.T, handler http.Handler, authHeader string) string {
	t.Helper()
	createReq := newRequest(t, http.MethodPost, "/sandboxes", map[string]any{"image": "ubuntu:24.04", "cpu": 1})
	if authHeader != "" {
		createReq.Header.Set("Authorization", authHeader)
	}
	createRR := httptest.NewRecorder()
	handler.ServeHTTP(createRR, createReq)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("expected 201 create, got %d body=%s", createRR.Code, createRR.Body.String())
	}
	return decodeJSON(t, createRR)["sandbox_id"].(string)
}

func TestRunCodeNodeAndPythonSuccess(t *testing.T) {
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	validator := auth.NewValidator("secret", "traforetto", "traforetto-api", func() time.Time { return now })
	svc := NewService(Config{
		WorkerID:       "worker-a",
		Hostname:       "worker-a.local",
		Validator:      validator,
		Clock:          func() time.Time { return now },
		TotalCores:     4,
		TotalMemoryMiB: 4096,
	})
	handler := svc.Handler()

	counter := 0
	nextAuth := func(client string) string {
		counter++
		return "Bearer " + makeJWT(t, "secret", client, fmt.Sprintf("jti-%s-%d", client, counter), now)
	}

	sandboxID := createSandboxWithAuth(t, handler, nextAuth("client-a"))

	nodeReq := newRequest(t, http.MethodPost, "/sandboxes/"+sandboxID+"/exec/code", map[string]any{
		"code":    "console.log('hello-node')",
		"runtime": "node",
		"wait":    true,
	})
	nodeReq.Header.Set("Authorization", nextAuth("client-a"))
	nodeRR := httptest.NewRecorder()
	handler.ServeHTTP(nodeRR, nodeReq)
	if nodeRR.Code != http.StatusOK {
		t.Fatalf("expected 200 for node runCode, got %d body=%s", nodeRR.Code, nodeRR.Body.String())
	}
	nodePayload := decodeJSON(t, nodeRR)
	if nodePayload["runtime"] != "node" {
		t.Fatalf("expected runtime=node, got %v", nodePayload["runtime"])
	}
	if nodePayload["status"] != "exited" {
		t.Fatalf("expected status=exited, got %v", nodePayload["status"])
	}
	if nodePayload["stdout"] != "hello-node\n" {
		t.Fatalf("unexpected node stdout: %q", nodePayload["stdout"])
	}
	if int(nodePayload["exit_code"].(float64)) != 0 {
		t.Fatalf("expected node exit_code=0, got %v", nodePayload["exit_code"])
	}

	pythonReq := newRequest(t, http.MethodPost, "/sandboxes/"+sandboxID+"/exec/code", map[string]any{
		"code":    "print('hello-python')",
		"runtime": "python",
		"wait":    true,
	})
	pythonReq.Header.Set("Authorization", nextAuth("client-a"))
	pythonRR := httptest.NewRecorder()
	handler.ServeHTTP(pythonRR, pythonReq)
	if pythonRR.Code != http.StatusOK {
		t.Fatalf("expected 200 for python runCode, got %d body=%s", pythonRR.Code, pythonRR.Body.String())
	}
	pythonPayload := decodeJSON(t, pythonRR)
	if pythonPayload["runtime"] != "python" {
		t.Fatalf("expected runtime=python, got %v", pythonPayload["runtime"])
	}
	if pythonPayload["stdout"] != "hello-python\n" {
		t.Fatalf("unexpected python stdout: %q", pythonPayload["stdout"])
	}
	if int(pythonPayload["exit_code"].(float64)) != 0 {
		t.Fatalf("expected python exit_code=0, got %v", pythonPayload["exit_code"])
	}
}

func TestRunCodeErrorsAndAsyncMode(t *testing.T) {
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	validator := auth.NewValidator("secret", "traforetto", "traforetto-api", func() time.Time { return now })
	svc := NewService(Config{
		WorkerID:       "worker-a",
		Hostname:       "worker-a.local",
		Validator:      validator,
		Clock:          func() time.Time { return now },
		TotalCores:     4,
		TotalMemoryMiB: 4096,
	})
	handler := svc.Handler()

	counter := 0
	nextAuth := func(client string) string {
		counter++
		return "Bearer " + makeJWT(t, "secret", client, fmt.Sprintf("jti-%s-%d", client, counter), now)
	}

	sandboxID := createSandboxWithAuth(t, handler, nextAuth("client-a"))

	runtimeErrReq := newRequest(t, http.MethodPost, "/sandboxes/"+sandboxID+"/exec/code", map[string]any{
		"code":    "throw new Error('boom')",
		"runtime": "node",
		"wait":    true,
	})
	runtimeErrReq.Header.Set("Authorization", nextAuth("client-a"))
	runtimeErrRR := httptest.NewRecorder()
	handler.ServeHTTP(runtimeErrRR, runtimeErrReq)
	if runtimeErrRR.Code != http.StatusOK {
		t.Fatalf("expected 200 runtime error response, got %d body=%s", runtimeErrRR.Code, runtimeErrRR.Body.String())
	}
	runtimeErrPayload := decodeJSON(t, runtimeErrRR)
	if int(runtimeErrPayload["exit_code"].(float64)) == 0 {
		t.Fatalf("expected non-zero exit_code for runtime error")
	}

	syntaxErrReq := newRequest(t, http.MethodPost, "/sandboxes/"+sandboxID+"/exec/code", map[string]any{
		"code":    "print('oops'",
		"runtime": "python",
		"wait":    true,
	})
	syntaxErrReq.Header.Set("Authorization", nextAuth("client-a"))
	syntaxErrRR := httptest.NewRecorder()
	handler.ServeHTTP(syntaxErrRR, syntaxErrReq)
	if syntaxErrRR.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 syntax error response, got %d body=%s", syntaxErrRR.Code, syntaxErrRR.Body.String())
	}
	syntaxErrPayload := decodeJSON(t, syntaxErrRR)
	if syntaxErrPayload["error"] != "syntax_error" {
		t.Fatalf("expected syntax_error payload, got %v", syntaxErrPayload["error"])
	}

	asyncReq := newRequest(t, http.MethodPost, "/sandboxes/"+sandboxID+"/exec/code", map[string]any{
		"code":    "print('later')",
		"runtime": "python",
		"wait":    false,
	})
	asyncReq.Header.Set("Authorization", nextAuth("client-a"))
	asyncRR := httptest.NewRecorder()
	handler.ServeHTTP(asyncRR, asyncReq)
	if asyncRR.Code != http.StatusAccepted {
		t.Fatalf("expected 202 async response, got %d body=%s", asyncRR.Code, asyncRR.Body.String())
	}
	asyncPayload := decodeJSON(t, asyncRR)
	if asyncPayload["status"] != "running" {
		t.Fatalf("expected status=running, got %v", asyncPayload["status"])
	}
	execID := asyncPayload["exec_id"].(string)
	if asyncPayload["poll_url"] == "" || asyncPayload["frames_url"] == "" {
		t.Fatalf("expected poll_url and frames_url in async response")
	}

	var pollPayload map[string]any
	for i := 0; i < 20; i++ {
		pollReq := newRequest(t, http.MethodGet, "/sandboxes/"+sandboxID+"/exec/"+execID, nil)
		pollReq.Header.Set("Authorization", nextAuth("client-a"))
		pollRR := httptest.NewRecorder()
		handler.ServeHTTP(pollRR, pollReq)
		if pollRR.Code != http.StatusOK {
			t.Fatalf("expected 200 while polling exec, got %d body=%s", pollRR.Code, pollRR.Body.String())
		}
		pollPayload = decodeJSON(t, pollRR)
		if pollPayload["status"] == "exited" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if pollPayload["status"] != "exited" {
		t.Fatalf("expected async exec to finish, last status=%v", pollPayload["status"])
	}
}

func TestFilesystemRoundtripStatListAndRemove(t *testing.T) {
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	validator := auth.NewValidator("secret", "traforetto", "traforetto-api", func() time.Time { return now })
	svc := NewService(Config{
		Hostname:       "worker-a.local",
		Validator:      validator,
		Clock:          func() time.Time { return now },
		TotalCores:     4,
		TotalMemoryMiB: 4096,
	})
	handler := svc.Handler()

	counter := 0
	nextAuth := func(client string) string {
		counter++
		return "Bearer " + makeJWT(t, "secret", client, fmt.Sprintf("jti-%s-%d", client, counter), now)
	}

	sandboxID := createSandboxWithAuth(t, handler, nextAuth("client-a"))

	writeUTF8Req := newRequest(t, http.MethodPut, "/sandboxes/"+sandboxID+"/files?path=/workspace/a.txt", map[string]any{
		"content":  "Hello",
		"encoding": "utf8",
	})
	writeUTF8Req.Header.Set("Authorization", nextAuth("client-a"))
	writeUTF8RR := httptest.NewRecorder()
	handler.ServeHTTP(writeUTF8RR, writeUTF8Req)
	if writeUTF8RR.Code != http.StatusOK {
		t.Fatalf("expected 200 write utf8, got %d body=%s", writeUTF8RR.Code, writeUTF8RR.Body.String())
	}
	if int(decodeJSON(t, writeUTF8RR)["bytes_written"].(float64)) != 5 {
		t.Fatalf("expected bytes_written=5")
	}

	writeNestedReq := newRequest(t, http.MethodPut, "/sandboxes/"+sandboxID+"/files?path=/workspace/a.txt/child.txt", map[string]any{
		"content":  "blocked",
		"encoding": "utf8",
	})
	writeNestedReq.Header.Set("Authorization", nextAuth("client-a"))
	writeNestedRR := httptest.NewRecorder()
	handler.ServeHTTP(writeNestedRR, writeNestedReq)
	if writeNestedRR.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when parent path is a file, got %d body=%s", writeNestedRR.Code, writeNestedRR.Body.String())
	}
	writeNestedPayload := decodeJSON(t, writeNestedRR)
	if writeNestedPayload["error"] != "path points to a file" {
		t.Fatalf("expected file-parent validation error, got %v", writeNestedPayload["error"])
	}

	readUTF8Req := newRequest(t, http.MethodGet, "/sandboxes/"+sandboxID+"/files?path=/workspace/a.txt", nil)
	readUTF8Req.Header.Set("Authorization", nextAuth("client-a"))
	readUTF8RR := httptest.NewRecorder()
	handler.ServeHTTP(readUTF8RR, readUTF8Req)
	if readUTF8RR.Code != http.StatusOK {
		t.Fatalf("expected 200 read utf8, got %d body=%s", readUTF8RR.Code, readUTF8RR.Body.String())
	}
	readUTF8Payload := decodeJSON(t, readUTF8RR)
	if readUTF8Payload["content"] != "Hello" {
		t.Fatalf("expected utf8 content Hello, got %v", readUTF8Payload["content"])
	}

	appendReq := newRequest(t, http.MethodPut, "/sandboxes/"+sandboxID+"/files?path=/workspace/a.txt", map[string]any{
		"content":  "IQ==",
		"encoding": "base64",
		"append":   true,
	})
	appendReq.Header.Set("Authorization", nextAuth("client-a"))
	appendRR := httptest.NewRecorder()
	handler.ServeHTTP(appendRR, appendReq)
	if appendRR.Code != http.StatusOK {
		t.Fatalf("expected 200 append write, got %d body=%s", appendRR.Code, appendRR.Body.String())
	}

	readB64Req := newRequest(t, http.MethodGet, "/sandboxes/"+sandboxID+"/files?path=/workspace/a.txt&encoding=base64", nil)
	readB64Req.Header.Set("Authorization", nextAuth("client-a"))
	readB64RR := httptest.NewRecorder()
	handler.ServeHTTP(readB64RR, readB64Req)
	if readB64RR.Code != http.StatusOK {
		t.Fatalf("expected 200 read base64, got %d body=%s", readB64RR.Code, readB64RR.Body.String())
	}
	if decodeJSON(t, readB64RR)["content"] != "SGVsbG8h" {
		t.Fatalf("expected base64 content SGVsbG8h")
	}

	statMissingReq := newRequest(t, http.MethodGet, "/sandboxes/"+sandboxID+"/files/stat?path=/workspace/missing.txt", nil)
	statMissingReq.Header.Set("Authorization", nextAuth("client-a"))
	statMissingRR := httptest.NewRecorder()
	handler.ServeHTTP(statMissingRR, statMissingReq)
	if statMissingRR.Code != http.StatusOK {
		t.Fatalf("expected 200 stat missing, got %d body=%s", statMissingRR.Code, statMissingRR.Body.String())
	}
	if decodeJSON(t, statMissingRR)["exists"] != false {
		t.Fatalf("expected exists=false for missing stat")
	}

	mkdirReq := newRequest(t, http.MethodPost, "/sandboxes/"+sandboxID+"/files/mkdir", map[string]any{
		"path":      "/workspace/src",
		"recursive": true,
	})
	mkdirReq.Header.Set("Authorization", nextAuth("client-a"))
	mkdirRR := httptest.NewRecorder()
	handler.ServeHTTP(mkdirRR, mkdirReq)
	if mkdirRR.Code != http.StatusOK {
		t.Fatalf("expected 200 mkdir, got %d body=%s", mkdirRR.Code, mkdirRR.Body.String())
	}

	writeSrcReq := newRequest(t, http.MethodPut, "/sandboxes/"+sandboxID+"/files?path=/workspace/src/main.txt", map[string]any{
		"content":  "ok",
		"encoding": "utf8",
	})
	writeSrcReq.Header.Set("Authorization", nextAuth("client-a"))
	writeSrcRR := httptest.NewRecorder()
	handler.ServeHTTP(writeSrcRR, writeSrcReq)
	if writeSrcRR.Code != http.StatusOK {
		t.Fatalf("expected 200 write src file, got %d body=%s", writeSrcRR.Code, writeSrcRR.Body.String())
	}

	listReq := newRequest(t, http.MethodGet, "/sandboxes/"+sandboxID+"/files/list?path=/workspace&recursive=false", nil)
	listReq.Header.Set("Authorization", nextAuth("client-a"))
	listRR := httptest.NewRecorder()
	handler.ServeHTTP(listRR, listReq)
	if listRR.Code != http.StatusOK {
		t.Fatalf("expected 200 list, got %d body=%s", listRR.Code, listRR.Body.String())
	}
	listPayload := decodeJSON(t, listRR)
	rawEntries, ok := listPayload["entries"].([]any)
	if !ok || len(rawEntries) < 2 {
		t.Fatalf("expected list entries to include file and directory, got %v", listPayload["entries"])
	}
	hasFile := false
	hasDir := false
	for _, raw := range rawEntries {
		entry := raw.(map[string]any)
		if entry["path"] == "/workspace/a.txt" && entry["type"] == "file" {
			hasFile = true
		}
		if entry["path"] == "/workspace/src" && entry["type"] == "directory" {
			hasDir = true
		}
	}
	if !hasFile || !hasDir {
		t.Fatalf("expected list entries to include /workspace/a.txt and /workspace/src, got %v", rawEntries)
	}

	removeDirNoRecursiveReq := newRequest(t, http.MethodDelete, "/sandboxes/"+sandboxID+"/files?path=/workspace/src&recursive=false", nil)
	removeDirNoRecursiveReq.Header.Set("Authorization", nextAuth("client-a"))
	removeDirNoRecursiveRR := httptest.NewRecorder()
	handler.ServeHTTP(removeDirNoRecursiveRR, removeDirNoRecursiveReq)
	if removeDirNoRecursiveRR.Code != http.StatusConflict {
		t.Fatalf("expected 409 for non-empty dir without recursive, got %d body=%s", removeDirNoRecursiveRR.Code, removeDirNoRecursiveRR.Body.String())
	}

	removeDirRecursiveReq := newRequest(t, http.MethodDelete, "/sandboxes/"+sandboxID+"/files?path=/workspace/src&recursive=true", nil)
	removeDirRecursiveReq.Header.Set("Authorization", nextAuth("client-a"))
	removeDirRecursiveRR := httptest.NewRecorder()
	handler.ServeHTTP(removeDirRecursiveRR, removeDirRecursiveReq)
	if removeDirRecursiveRR.Code != http.StatusNoContent {
		t.Fatalf("expected 204 recursive dir delete, got %d body=%s", removeDirRecursiveRR.Code, removeDirRecursiveRR.Body.String())
	}

	statDeletedReq := newRequest(t, http.MethodGet, "/sandboxes/"+sandboxID+"/files/stat?path=/workspace/src/main.txt", nil)
	statDeletedReq.Header.Set("Authorization", nextAuth("client-a"))
	statDeletedRR := httptest.NewRecorder()
	handler.ServeHTTP(statDeletedRR, statDeletedReq)
	if statDeletedRR.Code != http.StatusOK {
		t.Fatalf("expected 200 for stat deleted path, got %d body=%s", statDeletedRR.Code, statDeletedRR.Body.String())
	}
	if decodeJSON(t, statDeletedRR)["exists"] != false {
		t.Fatalf("expected exists=false after recursive delete")
	}
}

func TestProxyForwardingAndPortURLDiscovery(t *testing.T) {
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	validator := auth.NewValidator("secret", "traforetto", "traforetto-api", func() time.Time { return now })
	svc := NewService(Config{
		Hostname:       "worker-a.local",
		Validator:      validator,
		Clock:          func() time.Time { return now },
		TotalCores:     4,
		TotalMemoryMiB: 4096,
	})
	handler := svc.Handler()

	counter := 0
	nextAuth := func(client string) string {
		counter++
		return "Bearer " + makeJWT(t, "secret", client, fmt.Sprintf("jti-%s-%d", client, counter), now)
	}

	sandboxID := createSandboxWithAuth(t, handler, nextAuth("client-a"))

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Echo-Sandbox", r.Header.Get("X-Traforetto-Sandbox-Id"))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"method": r.Method,
			"path":   r.URL.Path,
			"query":  r.URL.RawQuery,
			"body":   string(body),
		})
	}))
	defer upstream.Close()

	parsedUpstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	upstreamPort, err := strconv.Atoi(parsedUpstreamURL.Port())
	if err != nil {
		t.Fatalf("parse upstream port: %v", err)
	}

	proxyReq := httptest.NewRequest(http.MethodPost, "/sandboxes/"+sandboxID+"/proxy/"+strconv.Itoa(upstreamPort)+"/hello/world?x=1", bytes.NewBufferString("ping"))
	proxyReq.Header.Set("Authorization", nextAuth("client-a"))
	proxyReq.Header.Set("Content-Type", "text/plain")
	proxyRR := httptest.NewRecorder()
	handler.ServeHTTP(proxyRR, proxyReq)
	if proxyRR.Code != http.StatusOK {
		t.Fatalf("expected 200 proxy response, got %d body=%s", proxyRR.Code, proxyRR.Body.String())
	}
	if proxyRR.Header().Get("X-Echo-Sandbox") != sandboxID {
		t.Fatalf("expected X-Echo-Sandbox=%s, got %s", sandboxID, proxyRR.Header().Get("X-Echo-Sandbox"))
	}
	proxyPayload := decodeJSON(t, proxyRR)
	if proxyPayload["method"] != http.MethodPost {
		t.Fatalf("expected proxied method POST, got %v", proxyPayload["method"])
	}
	if proxyPayload["path"] != "/hello/world" {
		t.Fatalf("expected proxied path /hello/world, got %v", proxyPayload["path"])
	}
	if proxyPayload["query"] != "x=1" {
		t.Fatalf("expected proxied query x=1, got %v", proxyPayload["query"])
	}
	if proxyPayload["body"] != "ping" {
		t.Fatalf("expected proxied body ping, got %v", proxyPayload["body"])
	}

	proxyTrailingReq := httptest.NewRequest(http.MethodGet, "/sandboxes/"+sandboxID+"/proxy/"+strconv.Itoa(upstreamPort)+"/app/?x=2", nil)
	proxyTrailingReq.Header.Set("Authorization", nextAuth("client-a"))
	proxyTrailingRR := httptest.NewRecorder()
	handler.ServeHTTP(proxyTrailingRR, proxyTrailingReq)
	if proxyTrailingRR.Code != http.StatusOK {
		t.Fatalf("expected 200 proxy response with trailing slash, got %d body=%s", proxyTrailingRR.Code, proxyTrailingRR.Body.String())
	}
	proxyTrailingPayload := decodeJSON(t, proxyTrailingRR)
	if proxyTrailingPayload["path"] != "/app/" {
		t.Fatalf("expected proxied path /app/, got %v", proxyTrailingPayload["path"])
	}
	if proxyTrailingPayload["query"] != "x=2" {
		t.Fatalf("expected proxied query x=2, got %v", proxyTrailingPayload["query"])
	}

	urlReq := newRequest(t, http.MethodGet, "/sandboxes/"+sandboxID+"/ports/"+strconv.Itoa(upstreamPort)+"/url?protocol=https", nil)
	urlReq.Header.Set("Authorization", nextAuth("client-a"))
	urlReq.Host = "controller.example.com"
	urlRR := httptest.NewRecorder()
	handler.ServeHTTP(urlRR, urlReq)
	if urlRR.Code != http.StatusOK {
		t.Fatalf("expected 200 port url discovery, got %d body=%s", urlRR.Code, urlRR.Body.String())
	}
	expectedURL := fmt.Sprintf("https://controller.example.com/sandboxes/%s/proxy/%d", sandboxID, upstreamPort)
	if got := decodeJSON(t, urlRR)["url"]; got != expectedURL {
		t.Fatalf("expected discovered URL %s, got %v", expectedURL, got)
	}
}

func TestProdOwnershipAppliesToNewEndpoints(t *testing.T) {
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	validator := auth.NewValidator("secret", "traforetto", "traforetto-api", func() time.Time { return now })
	svc := NewService(Config{
		Hostname:       "worker-a.local",
		Validator:      validator,
		Clock:          func() time.Time { return now },
		TotalCores:     4,
		TotalMemoryMiB: 4096,
	})
	handler := svc.Handler()

	counter := 0
	nextAuth := func(client string) string {
		counter++
		return "Bearer " + makeJWT(t, "secret", client, fmt.Sprintf("jti-%s-%d", client, counter), now)
	}

	sandboxID := createSandboxWithAuth(t, handler, nextAuth("client-a"))

	runCodeReq := newRequest(t, http.MethodPost, "/sandboxes/"+sandboxID+"/exec/code", map[string]any{
		"code":    "print('x')",
		"runtime": "python",
	})
	runCodeReq.Header.Set("Authorization", nextAuth("client-b"))
	runCodeRR := httptest.NewRecorder()
	handler.ServeHTTP(runCodeRR, runCodeReq)
	if runCodeRR.Code != http.StatusForbidden {
		t.Fatalf("expected 403 runCode ownership enforcement, got %d body=%s", runCodeRR.Code, runCodeRR.Body.String())
	}

	statReq := newRequest(t, http.MethodGet, "/sandboxes/"+sandboxID+"/files/stat?path=/workspace/x.txt", nil)
	statReq.Header.Set("Authorization", nextAuth("client-b"))
	statRR := httptest.NewRecorder()
	handler.ServeHTTP(statRR, statReq)
	if statRR.Code != http.StatusForbidden {
		t.Fatalf("expected 403 file stat ownership enforcement, got %d body=%s", statRR.Code, statRR.Body.String())
	}

	urlReq := newRequest(t, http.MethodGet, "/sandboxes/"+sandboxID+"/ports/3000/url?protocol=https", nil)
	urlReq.Header.Set("Authorization", nextAuth("client-b"))
	urlRR := httptest.NewRecorder()
	handler.ServeHTTP(urlRR, urlReq)
	if urlRR.Code != http.StatusForbidden {
		t.Fatalf("expected 403 port URL ownership enforcement, got %d body=%s", urlRR.Code, urlRR.Body.String())
	}

	proxyReq := httptest.NewRequest(http.MethodGet, "/sandboxes/"+sandboxID+"/proxy/3000", nil)
	proxyReq.Header.Set("Authorization", nextAuth("client-b"))
	proxyRR := httptest.NewRecorder()
	handler.ServeHTTP(proxyRR, proxyReq)
	if proxyRR.Code != http.StatusForbidden {
		t.Fatalf("expected 403 proxy ownership enforcement, got %d body=%s", proxyRR.Code, proxyRR.Body.String())
	}
}

func TestDevModeNoAuthStillWorksForNewEndpoints(t *testing.T) {
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	svc := NewService(Config{
		Hostname:       "worker-a.local",
		Validator:      auth.NewValidator("", "", "", func() time.Time { return now }),
		Clock:          func() time.Time { return now },
		TotalCores:     4,
		TotalMemoryMiB: 4096,
	})
	handler := svc.Handler()

	sandboxID := createSandboxWithAuth(t, handler, "")

	runCodeReq := newRequest(t, http.MethodPost, "/sandboxes/"+sandboxID+"/exec/code", map[string]any{
		"code":    "print('dev')",
		"runtime": "python",
	})
	runCodeRR := httptest.NewRecorder()
	handler.ServeHTTP(runCodeRR, runCodeReq)
	if runCodeRR.Code != http.StatusOK {
		t.Fatalf("expected 200 runCode in dev mode, got %d body=%s", runCodeRR.Code, runCodeRR.Body.String())
	}
	if !strings.Contains(runCodeRR.Body.String(), "dev") {
		t.Fatalf("expected runCode output in dev mode response")
	}

	writeReq := newRequest(t, http.MethodPut, "/sandboxes/"+sandboxID+"/files?path=/workspace/dev.txt", map[string]any{
		"content":  "RGV2",
		"encoding": "base64",
	})
	writeRR := httptest.NewRecorder()
	handler.ServeHTTP(writeRR, writeReq)
	if writeRR.Code != http.StatusOK {
		t.Fatalf("expected 200 file write in dev mode, got %d body=%s", writeRR.Code, writeRR.Body.String())
	}

	statReq := newRequest(t, http.MethodGet, "/sandboxes/"+sandboxID+"/files/stat?path=/workspace/dev.txt", nil)
	statRR := httptest.NewRecorder()
	handler.ServeHTTP(statRR, statReq)
	if statRR.Code != http.StatusOK {
		t.Fatalf("expected 200 stat in dev mode, got %d body=%s", statRR.Code, statRR.Body.String())
	}
	if decodeJSON(t, statRR)["exists"] != true {
		t.Fatalf("expected exists=true in dev mode stat response")
	}

	urlReq := newRequest(t, http.MethodGet, "/sandboxes/"+sandboxID+"/ports/3000/url?protocol=http", nil)
	urlReq.Host = "controller.local"
	urlRR := httptest.NewRecorder()
	handler.ServeHTTP(urlRR, urlReq)
	if urlRR.Code != http.StatusOK {
		t.Fatalf("expected 200 URL discovery in dev mode, got %d body=%s", urlRR.Code, urlRR.Body.String())
	}
}
