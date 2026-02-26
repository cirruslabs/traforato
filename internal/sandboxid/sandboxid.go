package sandboxid

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

var (
	ErrMalformed = errors.New("malformed sandbox_id")
)

type Parsed struct {
	Raw       string
	BrokerID  string
	WorkerID  string
	LocalVMID string
}

const prefix = "sbx-"

var componentPattern = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

func ValidateComponentID(id string) error {
	trimmed := strings.TrimSpace(id)
	if trimmed == "" {
		return fmt.Errorf("id is required")
	}
	if strings.Contains(trimmed, "-") {
		return fmt.Errorf("id %q must not contain '-'", trimmed)
	}
	if !componentPattern.MatchString(trimmed) {
		return fmt.Errorf("id %q contains unsupported characters", trimmed)
	}
	return nil
}

func New(brokerID, workerID string, entropy io.Reader) (string, error) {
	if entropy == nil {
		return "", fmt.Errorf("entropy source is required")
	}
	if err := ValidateComponentID(brokerID); err != nil {
		return "", fmt.Errorf("invalid broker_id: %w", err)
	}
	if err := ValidateComponentID(workerID); err != nil {
		return "", fmt.Errorf("invalid worker_id: %w", err)
	}

	value, err := uuid.NewRandomFromReader(entropy)
	if err != nil {
		return "", err
	}
	if value.Version() != uuid.Version(4) {
		return "", fmt.Errorf("generated UUID is not v4")
	}
	return fmt.Sprintf("%s%s-%s-%s", prefix, brokerID, workerID, value.String()), nil
}

func Parse(id string) (Parsed, error) {
	if !strings.HasPrefix(id, prefix) {
		return Parsed{}, ErrMalformed
	}
	remainder := strings.TrimPrefix(id, prefix)
	parts := strings.SplitN(remainder, "-", 3)
	if len(parts) != 3 {
		return Parsed{}, ErrMalformed
	}
	brokerID := strings.TrimSpace(parts[0])
	workerID := strings.TrimSpace(parts[1])
	localVMID := strings.TrimSpace(parts[2])
	if brokerID == "" || workerID == "" || localVMID == "" {
		return Parsed{}, ErrMalformed
	}
	if err := ValidateComponentID(brokerID); err != nil {
		return Parsed{}, ErrMalformed
	}
	if err := ValidateComponentID(workerID); err != nil {
		return Parsed{}, ErrMalformed
	}
	parsedUUID, err := uuid.Parse(localVMID)
	if err != nil {
		return Parsed{}, ErrMalformed
	}
	if parsedUUID.Version() != uuid.Version(4) {
		return Parsed{}, ErrMalformed
	}
	if localVMID != parsedUUID.String() {
		return Parsed{}, ErrMalformed
	}
	return Parsed{
		Raw:       id,
		BrokerID:  brokerID,
		WorkerID:  workerID,
		LocalVMID: localVMID,
	}, nil
}
