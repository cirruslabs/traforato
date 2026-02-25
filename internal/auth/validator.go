package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrReplay       = errors.New("jwt replay detected")
)

type Claims struct {
	ClientID string `json:"client_id"`
	jwt.RegisteredClaims
}

type Principal struct {
	ClientID string
	JWTID    string
	Expires  time.Time
}

// Validator checks JWTs in production mode and becomes no-op in dev mode.
type Validator struct {
	mode     Mode
	secret   []byte
	issuer   string
	audience string
	nowFn    func() time.Time
	replays  *ReplayCache
}

func NewValidator(secret, issuer, audience string, nowFn func() time.Time) *Validator {
	if nowFn == nil {
		nowFn = time.Now
	}
	mode := ModeFromSecret(secret)
	return &Validator{
		mode:     mode,
		secret:   []byte(secret),
		issuer:   issuer,
		audience: audience,
		nowFn:    nowFn,
		replays:  NewReplayCache(nowFn),
	}
}

func (v *Validator) Mode() Mode {
	return v.mode
}

func (v *Validator) Authenticate(_ context.Context, authz string) (Principal, error) {
	if v.mode == ModeDev {
		return Principal{ClientID: "dev-mode", JWTID: "dev-mode"}, nil
	}
	token := strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))
	if token == "" || token == authz {
		return Principal{}, fmt.Errorf("%w: missing bearer token", ErrUnauthorized)
	}

	claims := &Claims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("%w: invalid signing method", ErrUnauthorized)
		}
		return v.secret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil || !parsed.Valid {
		return Principal{}, fmt.Errorf("%w: %v", ErrUnauthorized, err)
	}

	now := v.nowFn()
	if claims.ClientID == "" {
		return Principal{}, fmt.Errorf("%w: missing client_id claim", ErrUnauthorized)
	}
	if claims.Issuer == "" {
		return Principal{}, fmt.Errorf("%w: missing iss claim", ErrUnauthorized)
	}
	if v.issuer != "" && claims.Issuer != v.issuer {
		return Principal{}, fmt.Errorf("%w: invalid issuer", ErrUnauthorized)
	}
	if len(claims.Audience) == 0 {
		return Principal{}, fmt.Errorf("%w: missing aud claim", ErrUnauthorized)
	}
	if v.audience != "" {
		valid := false
		for _, aud := range claims.Audience {
			if aud == v.audience {
				valid = true
				break
			}
		}
		if !valid {
			return Principal{}, fmt.Errorf("%w: invalid audience", ErrUnauthorized)
		}
	}
	if claims.ExpiresAt == nil || claims.ExpiresAt.Time.IsZero() {
		return Principal{}, fmt.Errorf("%w: missing exp claim", ErrUnauthorized)
	}
	if !claims.ExpiresAt.After(now) {
		return Principal{}, fmt.Errorf("%w: expired token", ErrUnauthorized)
	}
	if claims.IssuedAt == nil || claims.IssuedAt.Time.IsZero() {
		return Principal{}, fmt.Errorf("%w: missing iat claim", ErrUnauthorized)
	}
	if claims.IssuedAt.After(now.Add(5 * time.Second)) {
		return Principal{}, fmt.Errorf("%w: invalid issued-at", ErrUnauthorized)
	}
	if claims.ID == "" {
		return Principal{}, fmt.Errorf("%w: missing jti claim", ErrUnauthorized)
	}
	if v.replays.SeenOrAdd(claims.ID, claims.ExpiresAt.Time) {
		return Principal{}, fmt.Errorf("%w: %s", ErrReplay, claims.ID)
	}

	return Principal{
		ClientID: claims.ClientID,
		JWTID:    claims.ID,
		Expires:  claims.ExpiresAt.Time,
	}, nil
}
