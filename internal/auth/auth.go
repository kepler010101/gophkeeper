package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// HashPassword hashes a password with bcrypt.
func HashPassword(pw string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(hash), nil
}

// VerifyPassword checks a plaintext password against a hash.
func VerifyPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

// GenerateJWT creates a signed JWT for userID.
func GenerateJWT(userID string, secret string, ttl time.Duration) (string, error) {
	if userID == "" {
		return "", fmt.Errorf("empty user id")
	}
	if secret == "" {
		return "", fmt.Errorf("empty secret")
	}
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Subject:   userID,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}
	return signed, nil
}

// ValidateJWT validates token and returns userID.
func ValidateJWT(tokenStr, secret string) (string, error) {
	if tokenStr == "" {
		return "", fmt.Errorf("empty token")
	}
	if secret == "" {
		return "", fmt.Errorf("empty secret")
	}
	claims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(secret), nil
	})
	if err != nil {
		return "", fmt.Errorf("parse jwt: %w", err)
	}
	if !token.Valid {
		return "", fmt.Errorf("invalid token")
	}
	if claims.Subject == "" {
		return "", fmt.Errorf("missing subject")
	}
	return claims.Subject, nil
}

type ctxKey string

// WithUserID stores userID in context.
func WithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, ctxKey("user_id"), userID)
}

// UserIDFromContext reads userID from context.
func UserIDFromContext(ctx context.Context) (string, bool) {
	val := ctx.Value(ctxKey("user_id"))
	if val == nil {
		return "", false
	}
	id, ok := val.(string)
	if !ok || id == "" {
		return "", false
	}
	return id, true
}
