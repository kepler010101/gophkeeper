package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gophkeeper/internal/crypto"
	"gophkeeper/internal/server/config"
	"gophkeeper/internal/server/handlers"
	"gophkeeper/internal/server/service"
	"gophkeeper/internal/server/storage"
	"gophkeeper/internal/version"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println(version.String())
		return
	}
	if err := run(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func run() error {
	cfg, err := config.LoadServerConfigFromEnv()
	if err != nil {
		return fmt.Errorf("config error: %w", err)
	}
	masterKey, err := crypto.LoadMasterKeyFromEnv("GOPHKEEPER_MASTER_KEY")
	if err != nil {
		return fmt.Errorf("master key error: %w", err)
	}
	baseCtx := context.Background()
	if err := applyMigrations(baseCtx, cfg.DatabaseURL, "./migrations"); err != nil {
		return fmt.Errorf("migrations error: %w", err)
	}
	store, err := storage.NewStore(baseCtx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("store error: %w", err)
	}
	svc := service.New(store, masterKey, cfg.JWTSecret)
	log.Printf("config addr=%s db=%s tls_cert=%s tls_key=%s payload_max=%d", cfg.Addr, sanitizeDBURL(cfg.DatabaseURL), cfg.TLSCertPath, cfg.TLSKeyPath, cfg.PayloadMaxBytes)
	handler := handlers.NewServer(cfg, svc)
	srv := &http.Server{
		Addr:         cfg.Addr,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServeTLS(cfg.TLSCertPath, cfg.TLSKeyPath)
	}()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	if os.Getenv("GOPHKEEPER_TESTING") == "1" {
		stop()
		ctx, stop = context.WithTimeout(context.Background(), 200*time.Millisecond)
	}
	defer stop()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := srv.Shutdown(shutdownCtx)
		cancel()
		store.Close()
		return err
	case err := <-errCh:
		store.Close()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func sanitizeDBURL(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil || u.User == nil {
		return dsn
	}
	if _, ok := u.User.Password(); ok {
		u.User = url.User(u.User.Username())
	}
	return u.String()
}
