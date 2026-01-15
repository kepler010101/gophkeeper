package auth

import (
	"context"
	"testing"
	"time"
)

func TestHashVerify(t *testing.T) {
	hash, err := HashPassword("pass123")
	if err != nil {
		t.Fatalf("hash error: %v", err)
	}

	if !VerifyPassword(hash, "pass123") {
		t.Fatalf("expected true")
	}

	if VerifyPassword(hash, "wrong") {
		t.Fatalf("expected false")
	}
}

func TestJWTGenerateValidate(t *testing.T) {
	secret := "secretsecretsecretsecretsecret12"
	token, err := GenerateJWT("user-1", secret, time.Minute)
	if err != nil {
		t.Fatalf("generate error: %v", err)
	}

	userID, err := ValidateJWT(token, secret)
	if err != nil {
		t.Fatalf("validate error: %v", err)
	}

	if userID != "user-1" {
		t.Fatalf("unexpected user id: %s", userID)
	}
}

func TestJWTExpired(t *testing.T) {
	secret := "secretsecretsecretsecretsecret12"
	token, err := GenerateJWT("user-1", secret, -time.Minute)
	if err != nil {
		t.Fatalf("generate error: %v", err)
	}

	_, err = ValidateJWT(token, secret)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestContextUserID(t *testing.T) {
	ctx := context.Background()

	_, ok := UserIDFromContext(ctx)
	if ok {
		t.Fatalf("expected false")
	}

	ctx = WithUserID(ctx, "u1")
	id, ok := UserIDFromContext(ctx)
	if !ok || id != "u1" {
		t.Fatalf("unexpected id")
	}
}
