package auth

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func makeToken(t *testing.T, secret string, now time.Time, override func(*Claims)) string {
	t.Helper()
	claims := &Claims{
		ClientID: "client-a",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "traforato",
			Audience:  jwt.ClaimStrings{"traforato-api"},
			ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now.Add(-1 * time.Minute)),
			ID:        "jti-123",
		},
	}
	if override != nil {
		override(claims)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	return signed
}

func TestModeFromSecret(t *testing.T) {
	if got := ModeFromSecret(""); got != ModeDev {
		t.Fatalf("expected dev mode, got %s", got)
	}
	if got := ModeFromSecret("s3cr3t"); got != ModeProd {
		t.Fatalf("expected prod mode, got %s", got)
	}
}

func TestAuthenticateProdSuccessAndReplayGuard(t *testing.T) {
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	validator := NewValidator("secret", "traforato", "traforato-api", func() time.Time { return now })
	token := makeToken(t, "secret", now, nil)

	principal, err := validator.Authenticate(context.Background(), "Bearer "+token)
	if err != nil {
		t.Fatalf("Authenticate() unexpected error: %v", err)
	}
	if principal.ClientID != "client-a" {
		t.Fatalf("expected client-a, got %q", principal.ClientID)
	}

	_, err = validator.Authenticate(context.Background(), "Bearer "+token)
	if err == nil {
		t.Fatal("expected replay error, got nil")
	}
}

func TestAuthenticateDevModeSkipsJWT(t *testing.T) {
	validator := NewValidator("", "traforato", "traforato-api", nil)
	if validator.Mode() != ModeDev {
		t.Fatalf("expected dev mode, got %s", validator.Mode())
	}
	principal, err := validator.Authenticate(context.Background(), "")
	if err != nil {
		t.Fatalf("Authenticate() unexpected error: %v", err)
	}
	if principal.ClientID != "dev-mode" {
		t.Fatalf("expected dev-mode client ID, got %q", principal.ClientID)
	}
}

func TestAuthenticateProdMissingClaims(t *testing.T) {
	now := time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC)
	validator := NewValidator("secret", "traforato", "traforato-api", func() time.Time { return now })
	token := makeToken(t, "secret", now, func(claims *Claims) {
		claims.ClientID = ""
	})

	_, err := validator.Authenticate(context.Background(), "Bearer "+token)
	if err == nil {
		t.Fatal("expected error for missing client_id")
	}
}
