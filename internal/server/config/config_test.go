package config

import (
	"encoding/base64"
	"testing"
)

func TestLoadServerConfigDefaults(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	t.Setenv("DATABASE_URL", "postgres://x")
	t.Setenv("GOPHKEEPER_JWT_SECRET", "12345678901234567890123456789012")
	t.Setenv("GOPHKEEPER_MASTER_KEY", base64.StdEncoding.EncodeToString(key))

	cfg, err := LoadServerConfigFromEnv()
	if err != nil {
		t.Fatalf("load error: %v", err)
	}
	if cfg.Addr != ":8443" {
		t.Fatalf("addr default")
	}
	if cfg.TLSCertPath == "" || cfg.TLSKeyPath == "" {
		t.Fatalf("tls defaults")
	}
	if cfg.PayloadMaxBytes != 10*1024*1024 {
		t.Fatalf("payload default")
	}
	if cfg.DatabaseURL != "postgres://x" {
		t.Fatalf("db url")
	}
}

func TestLoadServerConfigMissingDB(t *testing.T) {
	t.Setenv("GOPHKEEPER_JWT_SECRET", "12345678901234567890123456789012")
	t.Setenv("GOPHKEEPER_MASTER_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	_, err := LoadServerConfigFromEnv()
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestLoadServerConfigJWTTooShort(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://x")
	t.Setenv("GOPHKEEPER_JWT_SECRET", "short")
	t.Setenv("GOPHKEEPER_MASTER_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	_, err := LoadServerConfigFromEnv()
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestLoadServerConfigBadMasterKey(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://x")
	t.Setenv("GOPHKEEPER_JWT_SECRET", "12345678901234567890123456789012")
	t.Setenv("GOPHKEEPER_MASTER_KEY", "not-base64")
	_, err := LoadServerConfigFromEnv()
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestLoadServerConfigMasterKeyLen(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://x")
	t.Setenv("GOPHKEEPER_JWT_SECRET", "12345678901234567890123456789012")
	t.Setenv("GOPHKEEPER_MASTER_KEY", base64.StdEncoding.EncodeToString(make([]byte, 31)))
	_, err := LoadServerConfigFromEnv()
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestLoadServerConfigPayloadMax(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://x")
	t.Setenv("GOPHKEEPER_JWT_SECRET", "12345678901234567890123456789012")
	t.Setenv("GOPHKEEPER_MASTER_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("GOPHKEEPER_PAYLOAD_MAX", "abc")
	_, err := LoadServerConfigFromEnv()
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestLoadServerConfigOverrides(t *testing.T) {
	key := make([]byte, 32)
	t.Setenv("GOPHKEEPER_DB_DSN", "postgres://y")
	t.Setenv("GOPHKEEPER_JWT_SECRET", "12345678901234567890123456789012")
	t.Setenv("GOPHKEEPER_MASTER_KEY", base64.StdEncoding.EncodeToString(key))
	t.Setenv("GOPHKEEPER_ADDR", ":9443")
	t.Setenv("GOPHKEEPER_TLS_CERT", "c.crt")
	t.Setenv("GOPHKEEPER_TLS_KEY", "c.key")
	t.Setenv("GOPHKEEPER_PAYLOAD_MAX", "123")

	cfg, err := LoadServerConfigFromEnv()
	if err != nil {
		t.Fatalf("load error: %v", err)
	}
	if cfg.Addr != ":9443" || cfg.TLSCertPath != "c.crt" || cfg.TLSKeyPath != "c.key" {
		t.Fatalf("overrides failed")
	}
	if cfg.PayloadMaxBytes != 123 {
		t.Fatalf("payload override")
	}
	if cfg.DatabaseURL != "postgres://y" {
		t.Fatalf("db override")
	}
}
