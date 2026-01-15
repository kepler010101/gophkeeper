package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func applyMigrations(ctx context.Context, databaseURL, dir string) error {
	cfg, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		return fmt.Errorf("parse db url: %w", err)
	}
	cfg.ConnectTimeout = 5 * time.Second
	db := stdlib.OpenDB(*cfg)
	defer db.Close()
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(1 * time.Minute)

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		return fmt.Errorf("ping db: %w", err)
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("migrations path: %w", err)
	}
	path := filepath.ToSlash(absDir)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("migrate driver: %w", err)
	}
	m, err := migrate.NewWithDatabaseInstance("file://"+path, "postgres", driver)
	if err != nil {
		return fmt.Errorf("migrate init: %w", err)
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("migrate up: %w", err)
	}
	return nil
}
