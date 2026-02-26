package httputil

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/oklog/ulid/v2"
)

// ParsePlacementRetry parses the placement_retry query parameter.
func ParsePlacementRetry(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	retry, err := strconv.Atoi(raw)
	if err != nil || retry < 0 {
		return 0, errors.New("invalid placement_retry")
	}
	return retry, nil
}

// RequestID extracts X-Request-Id from the request or generates one.
func RequestID(r *http.Request) string {
	if requestID := strings.TrimSpace(r.Header.Get("X-Request-Id")); requestID != "" {
		return requestID
	}
	return ulid.Make().String()
}
