package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
)

// ServerConfig holds server settings.
type ServerConfig struct {
	Addr            string
	TLSCertPath     string
	TLSKeyPath      string
	DatabaseURL     string
	JWTSecret       string
	MasterKeyBase64 string
	PayloadMaxBytes int64
}

// LoadServerConfigFromEnv loads config from env vars.
func LoadServerConfigFromEnv() (ServerConfig, error) {
	cfg := ServerConfig{
		Addr:            ":8443",
		TLSCertPath:     "./certs/server.crt",
		TLSKeyPath:      "./certs/server.key",
		PayloadMaxBytes: 10 * 1024 * 1024,
	}

	if v := os.Getenv("GOPHKEEPER_ADDR"); v != "" {
		cfg.Addr = v
	}
	if v := os.Getenv("GOPHKEEPER_TLS_CERT"); v != "" {
		cfg.TLSCertPath = v
	}
	if v := os.Getenv("GOPHKEEPER_TLS_KEY"); v != "" {
		cfg.TLSKeyPath = v
	}
	if v := os.Getenv("GOPHKEEPER_DB_DSN"); v != "" {
		cfg.DatabaseURL = v
	}
	if cfg.DatabaseURL == "" {
		if v := os.Getenv("DATABASE_URL"); v != "" {
			cfg.DatabaseURL = v
		}
	}
	if v := os.Getenv("GOPHKEEPER_JWT_SECRET"); v != "" {
		cfg.JWTSecret = v
	}
	if v := os.Getenv("GOPHKEEPER_MASTER_KEY"); v != "" {
		cfg.MasterKeyBase64 = v
	}
	if v := os.Getenv("GOPHKEEPER_PAYLOAD_MAX"); v != "" {
		parsed, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return cfg, fmt.Errorf("invalid GOPHKEEPER_PAYLOAD_MAX: %w", err)
		}
		if parsed <= 0 {
			return cfg, fmt.Errorf("invalid GOPHKEEPER_PAYLOAD_MAX: %d", parsed)
		}
		cfg.PayloadMaxBytes = parsed
	}

	if cfg.DatabaseURL == "" {
		return cfg, fmt.Errorf("missing GOPHKEEPER_DB_DSN")
	}
	if cfg.JWTSecret == "" {
		return cfg, fmt.Errorf("missing GOPHKEEPER_JWT_SECRET")
	}
	if len(cfg.JWTSecret) < 32 {
		return cfg, fmt.Errorf("GOPHKEEPER_JWT_SECRET must be at least 32 characters")
	}
	if cfg.MasterKeyBase64 == "" {
		return cfg, fmt.Errorf("missing GOPHKEEPER_MASTER_KEY")
	}
	decoded, err := base64.StdEncoding.DecodeString(cfg.MasterKeyBase64)
	if err != nil {
		return cfg, fmt.Errorf("invalid GOPHKEEPER_MASTER_KEY: %w", err)
	}
	if len(decoded) != 32 {
		return cfg, fmt.Errorf("invalid GOPHKEEPER_MASTER_KEY length: %d", len(decoded))
	}

	return cfg, nil
}
