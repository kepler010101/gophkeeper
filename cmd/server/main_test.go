package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMainVersion(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"server", "--version"}
	out := captureStdout(func() {
		main()
	})
	if !strings.Contains(out, "gophkeeper version=") {
		t.Fatalf("version not printed")
	}
}

func TestSanitizeDBURL(t *testing.T) {
	dsn := "postgres://user:pass@localhost:5432/db?sslmode=disable"
	got := sanitizeDBURL(dsn)
	if strings.Contains(got, "pass") {
		t.Fatalf("password leaked")
	}
	if !strings.Contains(got, "user@") {
		t.Fatalf("user missing")
	}
	plain := "not a url"
	if sanitizeDBURL(plain) != plain {
		t.Fatalf("unexpected change")
	}
}

func TestRunConfigError(t *testing.T) {
	t.Setenv("GOPHKEEPER_DB_DSN", "")
	t.Setenv("DATABASE_URL", "")
	t.Setenv("GOPHKEEPER_JWT_SECRET", "")
	t.Setenv("GOPHKEEPER_MASTER_KEY", "")
	if err := run(); err == nil {
		t.Fatalf("expected error")
	}
}

func TestRunBadDSN(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	t.Setenv("GOPHKEEPER_DB_DSN", "bad")
	t.Setenv("GOPHKEEPER_JWT_SECRET", "secretsecretsecretsecretsecret12")
	t.Setenv("GOPHKEEPER_MASTER_KEY", key)
	if err := run(); err == nil {
		t.Fatalf("expected error")
	}
}

func TestRunTLSFailure(t *testing.T) {
	dsn := os.Getenv("GOPHKEEPER_TEST_DB")
	if dsn == "" {
		t.Skip("no test db")
	}
	adminDSN, err := toAdminDSN(dsn)
	if err != nil {
		t.Fatalf("admin dsn: %v", err)
	}
	dbName := fmt.Sprintf("gophkeeper_test_%d", time.Now().UnixNano())
	adminPool, err := pgxpool.New(context.Background(), adminDSN)
	if err != nil {
		t.Fatalf("admin pool: %v", err)
	}
	_, err = adminPool.Exec(context.Background(), "create database "+dbName)
	if err != nil {
		adminPool.Close()
		t.Fatalf("create db: %v", err)
	}
	adminPool.Close()

	u, _ := url.Parse(dsn)
	u.Path = "/" + dbName
	testDSN := u.String()

	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	t.Setenv("GOPHKEEPER_DB_DSN", testDSN)
	t.Setenv("GOPHKEEPER_JWT_SECRET", "secretsecretsecretsecretsecret12")
	t.Setenv("GOPHKEEPER_MASTER_KEY", key)
	t.Setenv("GOPHKEEPER_TLS_CERT", "nope.crt")
	t.Setenv("GOPHKEEPER_TLS_KEY", "nope.key")
	err = run()
	if err == nil {
		t.Fatalf("expected error")
	}

	adminPool, err = pgxpool.New(context.Background(), adminDSN)
	if err == nil {
		_, _ = adminPool.Exec(context.Background(), "drop database if exists "+dbName)
		adminPool.Close()
	}
}

func TestRunGracefulShutdown(t *testing.T) {
	dsn := os.Getenv("GOPHKEEPER_TEST_DB")
	if dsn == "" {
		t.Skip("no test db")
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(filepath.Join(wd, "..", "..")); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()
	adminDSN, err := toAdminDSN(dsn)
	if err != nil {
		t.Fatalf("admin dsn: %v", err)
	}
	dbName := fmt.Sprintf("gophkeeper_run_%d", time.Now().UnixNano())
	adminPool, err := pgxpool.New(context.Background(), adminDSN)
	if err != nil {
		t.Fatalf("admin pool: %v", err)
	}
	_, err = adminPool.Exec(context.Background(), "create database "+dbName)
	if err != nil {
		adminPool.Close()
		t.Fatalf("create db: %v", err)
	}
	adminPool.Close()

	u, _ := url.Parse(dsn)
	u.Path = "/" + dbName
	testDSN := u.String()

	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := writeTestCert(certPath, keyPath); err != nil {
		t.Fatalf("cert error: %v", err)
	}

	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	t.Setenv("GOPHKEEPER_DB_DSN", testDSN)
	t.Setenv("GOPHKEEPER_JWT_SECRET", "secretsecretsecretsecretsecret12")
	t.Setenv("GOPHKEEPER_MASTER_KEY", key)
	t.Setenv("GOPHKEEPER_TLS_CERT", certPath)
	t.Setenv("GOPHKEEPER_TLS_KEY", keyPath)
	t.Setenv("GOPHKEEPER_ADDR", "127.0.0.1:0")
	t.Setenv("GOPHKEEPER_TESTING", "1")

	if err := run(); err != nil {
		t.Fatalf("run error: %v", err)
	}

	adminPool, err = pgxpool.New(context.Background(), adminDSN)
	if err == nil {
		_, _ = adminPool.Exec(context.Background(), "drop database if exists "+dbName)
		adminPool.Close()
	}
}

func TestApplyMigrations(t *testing.T) {
	dsn := os.Getenv("GOPHKEEPER_TEST_DB")
	if dsn == "" {
		t.Skip("no test db")
	}
	dir := t.TempDir()
	m1 := []byte("create table if not exists t1 (id int);")
	m2 := []byte("create table if not exists t2 (id int);")
	if err := os.WriteFile(filepath.Join(dir, "001_one.up.sql"), m1, 0600); err != nil {
		t.Fatalf("write m1: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "002_two.up.sql"), m2, 0600); err != nil {
		t.Fatalf("write m2: %v", err)
	}
	if err := applyMigrations(context.Background(), dsn, dir); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := applyMigrations(context.Background(), dsn, dir); err != nil {
		t.Fatalf("apply again: %v", err)
	}

	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	var version int
	var dirty bool
	if err := pool.QueryRow(context.Background(), "select version, dirty from schema_migrations").Scan(&version, &dirty); err != nil {
		t.Fatalf("version: %v", err)
	}
	if version != 2 || dirty {
		t.Fatalf("unexpected state")
	}
	_, _ = pool.Exec(context.Background(), "drop table if exists t1")
	_, _ = pool.Exec(context.Background(), "drop table if exists t2")
	_, _ = pool.Exec(context.Background(), "drop table if exists schema_migrations")
}

func TestApplyMigrationsBadSQL(t *testing.T) {
	dsn := os.Getenv("GOPHKEEPER_TEST_DB")
	if dsn == "" {
		t.Skip("no test db")
	}
	dir := t.TempDir()
	m1 := []byte("create table if not exists t_bad (id int); bad sql;")
	if err := os.WriteFile(filepath.Join(dir, "001_bad.up.sql"), m1, 0600); err != nil {
		t.Fatalf("write m1: %v", err)
	}
	if err := applyMigrations(context.Background(), dsn, dir); err == nil {
		t.Fatalf("expected error")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err == nil {
		_, _ = pool.Exec(context.Background(), "drop table if exists t_bad")
		_, _ = pool.Exec(context.Background(), "drop table if exists schema_migrations")
		pool.Close()
	}
}

func toAdminDSN(dsn string) (string, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return "", err
	}
	u.Path = "/postgres"
	return u.String(), nil
}

func writeTestCert(certPath, keyPath string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return err
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(2 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}
	certOut, err := os.Create(certPath)
	if err != nil {
		return err
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		_ = certOut.Close()
		return err
	}
	_ = certOut.Close()

	keyOut, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	keyBytes := x509.MarshalPKCS1PrivateKey(priv)
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}); err != nil {
		_ = keyOut.Close()
		return err
	}
	return keyOut.Close()
}

func captureStdout(fn func()) string {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	fn()
	_ = w.Close()
	out, _ := io.ReadAll(r)
	os.Stdout = oldStdout
	return strings.TrimSpace(string(out))
}
