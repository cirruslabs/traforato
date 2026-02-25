package auth

import "strings"

// Mode controls whether JWT verification is enforced.
type Mode string

const (
	ModeProd Mode = "prod"
	ModeDev  Mode = "dev"
)

func ModeFromSecret(secret string) Mode {
	if strings.TrimSpace(secret) == "" {
		return ModeDev
	}
	return ModeProd
}
