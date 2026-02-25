package worker

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fedor/traforetto/internal/auth"
)

const (
	maxFileWriteBodyBytes = 10 << 20
	defaultListLimit      = 1000
)

var (
	errPathMissing      = errors.New("path query parameter is required")
	errPathInvalid      = errors.New("path must be an absolute path")
	errPathPointsToFile = errors.New("path points to a file")
)

type writeFileRequest struct {
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
	Append   bool   `json:"append"`
}

type mkdirRequest struct {
	Path      string `json:"path"`
	Recursive bool   `json:"recursive"`
}

type listEntry struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Type string `json:"type"`
	Size *int   `json:"size,omitempty"`
}

func (s *Service) handleWriteFile(w http.ResponseWriter, r *http.Request, principal auth.Principal, sandboxID string) {
	normalizedPath, err := normalizeSandboxPath(r.URL.Query().Get("path"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxFileWriteBodyBytes+1))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "failed to read body")
		return
	}
	if len(body) > maxFileWriteBodyBytes {
		s.writeError(w, http.StatusBadRequest, "body exceeds max size")
		return
	}

	content, appendMode, err := decodeWritePayload(r.Header.Get("Content-Type"), body)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	now := s.cfg.Clock().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	sbx, ok := s.sandboxes[sandboxID]
	if !ok {
		s.writeError(w, http.StatusNotFound, "sandbox not found")
		return
	}
	if err := s.ensureOwnership(principal, sbx.OwnerClientID); err != nil {
		s.writeOwnedError(w, err)
		return
	}
	if _, exists := sbx.dirs[normalizedPath]; exists {
		s.writeError(w, http.StatusBadRequest, "path points to a directory")
		return
	}

	if err := ensureParentDirsLocked(sbx, normalizedPath, now); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if appendMode {
		sbx.files[normalizedPath] = append(sbx.files[normalizedPath], content...)
	} else {
		sbx.files[normalizedPath] = append([]byte(nil), content...)
	}
	sbx.fileModTimes[normalizedPath] = now
	if parent := path.Dir(normalizedPath); parent != "." {
		sbx.dirModTimes[parent] = now
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"sandbox_id":    sandboxID,
		"path":          normalizedPath,
		"bytes_written": len(content),
		"bytes":         len(content),
	})
}

func (s *Service) handleGetFile(w http.ResponseWriter, r *http.Request, principal auth.Principal, sandboxID string) {
	normalizedPath, err := normalizeSandboxPath(r.URL.Query().Get("path"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	encoding := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("encoding")))
	if encoding == "" {
		encoding = "utf8"
	}
	if encoding != "utf8" && encoding != "base64" {
		s.writeError(w, http.StatusBadRequest, "encoding must be utf8 or base64")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	sbx, ok := s.sandboxes[sandboxID]
	if !ok {
		s.writeError(w, http.StatusNotFound, "sandbox not found")
		return
	}
	if err := s.ensureOwnership(principal, sbx.OwnerClientID); err != nil {
		s.writeOwnedError(w, err)
		return
	}

	file, ok := sbx.files[normalizedPath]
	if !ok {
		s.writeError(w, http.StatusNotFound, "file not found")
		return
	}

	content := string(file)
	if encoding == "base64" {
		content = base64.StdEncoding.EncodeToString(file)
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"sandbox_id": sandboxID,
		"path":       normalizedPath,
		"type":       "file",
		"encoding":   encoding,
		"content":    content,
		"bytes":      len(file),
	})
}

func (s *Service) handleGetFileStat(w http.ResponseWriter, r *http.Request, principal auth.Principal, sandboxID string) {
	normalizedPath, err := normalizeSandboxPath(r.URL.Query().Get("path"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	sbx, ok := s.sandboxes[sandboxID]
	if !ok {
		s.writeError(w, http.StatusNotFound, "sandbox not found")
		return
	}
	if err := s.ensureOwnership(principal, sbx.OwnerClientID); err != nil {
		s.writeOwnedError(w, err)
		return
	}

	if file, exists := sbx.files[normalizedPath]; exists {
		modifiedAt := sbx.fileModTimes[normalizedPath]
		if modifiedAt.IsZero() {
			modifiedAt = sbx.CreatedAt
		}
		s.writeJSON(w, http.StatusOK, map[string]any{
			"sandbox_id":  sandboxID,
			"path":        normalizedPath,
			"exists":      true,
			"type":        "file",
			"size":        len(file),
			"modified_at": modifiedAt,
		})
		return
	}
	if _, exists := sbx.dirs[normalizedPath]; exists {
		modifiedAt := sbx.dirModTimes[normalizedPath]
		if modifiedAt.IsZero() {
			modifiedAt = sbx.CreatedAt
		}
		s.writeJSON(w, http.StatusOK, map[string]any{
			"sandbox_id":  sandboxID,
			"path":        normalizedPath,
			"exists":      true,
			"type":        "directory",
			"size":        0,
			"modified_at": modifiedAt,
		})
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"sandbox_id": sandboxID,
		"path":       normalizedPath,
		"exists":     false,
	})
}

func (s *Service) handleListFiles(w http.ResponseWriter, r *http.Request, principal auth.Principal, sandboxID string) {
	normalizedPath, err := normalizeSandboxPath(r.URL.Query().Get("path"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	recursive, err := parseBoolQuery(r.URL.Query().Get("recursive"), false)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "recursive must be true or false")
		return
	}
	limit := defaultListLimit
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			s.writeError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		limit = parsed
	}
	cursor := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("cursor")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			s.writeError(w, http.StatusBadRequest, "cursor must be a non-negative integer")
			return
		}
		cursor = parsed
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	sbx, ok := s.sandboxes[sandboxID]
	if !ok {
		s.writeError(w, http.StatusNotFound, "sandbox not found")
		return
	}
	if err := s.ensureOwnership(principal, sbx.OwnerClientID); err != nil {
		s.writeOwnedError(w, err)
		return
	}
	if _, exists := sbx.dirs[normalizedPath]; !exists {
		s.writeError(w, http.StatusNotFound, "directory not found")
		return
	}

	entriesByPath := make(map[string]listEntry)
	for dirPath := range sbx.dirs {
		if !isDescendantPath(dirPath, normalizedPath) {
			continue
		}
		if recursive {
			entriesByPath[dirPath] = newDirectoryEntry(dirPath)
			continue
		}
		childPath, ok := immediateChildPath(normalizedPath, dirPath)
		if !ok {
			continue
		}
		entriesByPath[childPath] = newDirectoryEntry(childPath)
	}

	for filePath, file := range sbx.files {
		if !isDescendantPath(filePath, normalizedPath) {
			continue
		}
		if recursive {
			entriesByPath[filePath] = newFileEntry(filePath, len(file))
			continue
		}
		childPath, ok := immediateChildPath(normalizedPath, filePath)
		if !ok {
			continue
		}
		if childPath == filePath {
			entriesByPath[filePath] = newFileEntry(filePath, len(file))
			continue
		}
		entriesByPath[childPath] = newDirectoryEntry(childPath)
	}

	entries := make([]listEntry, 0, len(entriesByPath))
	for _, entry := range entriesByPath {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Path < entries[j].Path
	})

	if cursor > len(entries) {
		cursor = len(entries)
	}
	end := cursor + limit
	if end > len(entries) {
		end = len(entries)
	}

	var nextCursor any
	if end < len(entries) {
		nextCursor = strconv.Itoa(end)
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"sandbox_id":  sandboxID,
		"path":        normalizedPath,
		"entries":     entries[cursor:end],
		"next_cursor": nextCursor,
	})
}

func (s *Service) handleMkdirFiles(w http.ResponseWriter, r *http.Request, principal auth.Principal, sandboxID string) {
	var req mkdirRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	normalizedPath, err := normalizeSandboxPath(req.Path)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if normalizedPath == "/" {
		s.writeJSON(w, http.StatusOK, map[string]any{
			"sandbox_id": sandboxID,
			"path":       normalizedPath,
			"created":    false,
		})
		return
	}

	now := s.cfg.Clock().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	sbx, ok := s.sandboxes[sandboxID]
	if !ok {
		s.writeError(w, http.StatusNotFound, "sandbox not found")
		return
	}
	if err := s.ensureOwnership(principal, sbx.OwnerClientID); err != nil {
		s.writeOwnedError(w, err)
		return
	}
	if _, exists := sbx.files[normalizedPath]; exists {
		s.writeError(w, http.StatusBadRequest, errPathPointsToFile.Error())
		return
	}
	if _, exists := sbx.dirs[normalizedPath]; exists {
		s.writeJSON(w, http.StatusOK, map[string]any{
			"sandbox_id": sandboxID,
			"path":       normalizedPath,
			"created":    false,
		})
		return
	}

	parent := path.Dir(normalizedPath)
	if !req.Recursive {
		if _, exists := sbx.dirs[parent]; !exists {
			s.writeError(w, http.StatusNotFound, "parent directory not found")
			return
		}
		createDirectoryLocked(sbx, normalizedPath, now)
	} else {
		if err := createDirectoryTreeLocked(sbx, normalizedPath, now); err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	sbx.dirModTimes[parent] = now

	s.writeJSON(w, http.StatusOK, map[string]any{
		"sandbox_id": sandboxID,
		"path":       normalizedPath,
		"created":    true,
	})
}

func (s *Service) handleDeleteFiles(w http.ResponseWriter, r *http.Request, principal auth.Principal, sandboxID string) {
	normalizedPath, err := normalizeSandboxPath(r.URL.Query().Get("path"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if normalizedPath == "/" {
		s.writeError(w, http.StatusBadRequest, "cannot remove root directory")
		return
	}

	recursive, err := parseBoolQuery(r.URL.Query().Get("recursive"), false)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "recursive must be true or false")
		return
	}
	force, err := parseBoolQuery(r.URL.Query().Get("force"), false)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "force must be true or false")
		return
	}

	now := s.cfg.Clock().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	sbx, ok := s.sandboxes[sandboxID]
	if !ok {
		s.writeError(w, http.StatusNotFound, "sandbox not found")
		return
	}
	if err := s.ensureOwnership(principal, sbx.OwnerClientID); err != nil {
		s.writeOwnedError(w, err)
		return
	}

	if _, exists := sbx.files[normalizedPath]; exists {
		delete(sbx.files, normalizedPath)
		delete(sbx.fileModTimes, normalizedPath)
		sbx.dirModTimes[path.Dir(normalizedPath)] = now
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if _, exists := sbx.dirs[normalizedPath]; !exists {
		if force {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		s.writeError(w, http.StatusNotFound, "path not found")
		return
	}

	if !recursive && directoryHasChildrenLocked(sbx, normalizedPath) {
		s.writeError(w, http.StatusConflict, "directory is not empty")
		return
	}

	for filePath := range sbx.files {
		if filePath == normalizedPath || isDescendantPath(filePath, normalizedPath) {
			delete(sbx.files, filePath)
			delete(sbx.fileModTimes, filePath)
		}
	}
	for dirPath := range sbx.dirs {
		if dirPath == normalizedPath || isDescendantPath(dirPath, normalizedPath) {
			delete(sbx.dirs, dirPath)
			delete(sbx.dirModTimes, dirPath)
		}
	}
	sbx.dirModTimes[path.Dir(normalizedPath)] = now

	w.WriteHeader(http.StatusNoContent)
}

func decodeWritePayload(contentType string, body []byte) ([]byte, bool, error) {
	contentType = strings.ToLower(contentType)
	if !strings.Contains(contentType, "application/json") {
		return body, false, nil
	}

	var req writeFileRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, false, errors.New("invalid request body")
	}
	encoding := strings.ToLower(strings.TrimSpace(req.Encoding))
	if encoding == "" {
		encoding = "base64"
	}

	switch encoding {
	case "base64":
		decoded, err := base64.StdEncoding.DecodeString(req.Content)
		if err != nil {
			return nil, false, errors.New("invalid base64 content")
		}
		return decoded, req.Append, nil
	case "utf8", "utf-8":
		return []byte(req.Content), req.Append, nil
	default:
		return nil, false, errors.New("encoding must be utf8 or base64")
	}
}

func normalizeSandboxPath(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errPathMissing
	}
	if !strings.HasPrefix(raw, "/") {
		return "", errPathInvalid
	}
	clean := path.Clean(raw)
	if clean == "." || !strings.HasPrefix(clean, "/") {
		return "", errPathInvalid
	}
	return clean, nil
}

func parseBoolQuery(raw string, defaultValue bool) (bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultValue, nil
	}
	parsed, err := strconv.ParseBool(raw)
	if err != nil {
		return false, err
	}
	return parsed, nil
}

func ensureParentDirsLocked(sbx *sandboxState, filePath string, now time.Time) error {
	parent := path.Dir(filePath)
	return createDirectoryTreeLocked(sbx, parent, now)
}

func createDirectoryTreeLocked(sbx *sandboxState, dirPath string, now time.Time) error {
	if dirPath == "." || dirPath == "" {
		return nil
	}
	if dirPath == "/" {
		createDirectoryLocked(sbx, "/", now)
		return nil
	}
	segments := strings.Split(strings.TrimPrefix(dirPath, "/"), "/")
	current := ""
	createDirectoryLocked(sbx, "/", now)
	for _, segment := range segments {
		if segment == "" {
			continue
		}
		current += "/" + segment
		if _, exists := sbx.files[current]; exists {
			return errPathPointsToFile
		}
		createDirectoryLocked(sbx, current, now)
	}
	return nil
}

func createDirectoryLocked(sbx *sandboxState, dirPath string, now time.Time) {
	if sbx.dirs == nil {
		sbx.dirs = make(map[string]struct{})
	}
	if sbx.dirModTimes == nil {
		sbx.dirModTimes = make(map[string]time.Time)
	}
	if _, exists := sbx.dirs[dirPath]; !exists {
		sbx.dirs[dirPath] = struct{}{}
	}
	if _, exists := sbx.dirModTimes[dirPath]; !exists {
		sbx.dirModTimes[dirPath] = now
	}
}

func isDescendantPath(candidate, base string) bool {
	if candidate == "" || base == "" {
		return false
	}
	if base == "/" {
		return candidate != "/"
	}
	if candidate == base {
		return false
	}
	return strings.HasPrefix(candidate, base+"/")
}

func immediateChildPath(base, candidate string) (string, bool) {
	if !isDescendantPath(candidate, base) {
		return "", false
	}
	var relative string
	if base == "/" {
		relative = strings.TrimPrefix(candidate, "/")
	} else {
		relative = strings.TrimPrefix(candidate, base+"/")
	}
	if relative == "" {
		return "", false
	}
	segment := strings.SplitN(relative, "/", 2)[0]
	if base == "/" {
		return "/" + segment, true
	}
	return base + "/" + segment, true
}

func directoryHasChildrenLocked(sbx *sandboxState, dirPath string) bool {
	for filePath := range sbx.files {
		if isDescendantPath(filePath, dirPath) {
			return true
		}
	}
	for candidateDir := range sbx.dirs {
		if isDescendantPath(candidateDir, dirPath) {
			return true
		}
	}
	return false
}

func newDirectoryEntry(dirPath string) listEntry {
	return listEntry{
		Name: path.Base(dirPath),
		Path: dirPath,
		Type: "directory",
	}
}

func newFileEntry(filePath string, size int) listEntry {
	sizeValue := size
	return listEntry{
		Name: path.Base(filePath),
		Path: filePath,
		Type: "file",
		Size: &sizeValue,
	}
}
