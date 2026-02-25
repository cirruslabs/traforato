package sandboxid

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
)

var (
	ErrMalformed = errors.New("malformed sandbox_id")

	idPattern = regexp.MustCompile(`^sbx_([0-9a-f]{32})_([0-9A-HJKMNP-TV-Z]{26})$`)
)

type Parsed struct {
	Raw        string
	WorkerHash string
	ULID       string
}

func WorkerHash(hostname string) string {
	sum := md5.Sum([]byte(strings.ToLower(strings.TrimSpace(hostname))))
	return hex.EncodeToString(sum[:])
}

func New(hostname string, entropy io.Reader) (string, error) {
	if entropy == nil {
		return "", fmt.Errorf("entropy source is required")
	}
	hash := WorkerHash(hostname)
	value, err := ulid.New(ulid.Timestamp(time.Now().UTC()), entropy)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("sbx_%s_%s", hash, strings.ToUpper(value.String())), nil
}

func Parse(id string) (Parsed, error) {
	matches := idPattern.FindStringSubmatch(id)
	if len(matches) != 3 {
		return Parsed{}, ErrMalformed
	}
	return Parsed{
		Raw:        id,
		WorkerHash: matches[1],
		ULID:       matches[2],
	}, nil
}
