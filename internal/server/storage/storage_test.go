package storage

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestNewStoreBadDSN(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := NewStore(ctx, "postgres://bad:bad@127.0.0.1:1/db?sslmode=disable")
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestStoreCloseNil(t *testing.T) {
	s := &Store{}
	s.Close()
}

func TestStoreCRUD(t *testing.T) {
	dsn := os.Getenv("GOPHKEEPER_TEST_DB")
	if dsn == "" {
		t.Skip("no test db")
	}
	ctx := context.Background()
	store, err := NewStore(ctx, dsn)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	defer store.Close()

	if err := setupSchema(ctx, store); err != nil {
		t.Fatalf("setup schema: %v", err)
	}

	userID, err := store.CreateUser(ctx, "user1", "hash1")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	gotUser, err := store.GetUserByUsername(ctx, "user1")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if gotUser.ID != userID || gotUser.Username != "user1" || gotUser.PasswordHash != "hash1" {
		t.Fatalf("user mismatch")
	}

	meta := json.RawMessage(`{"site":"example"}`)
	itemID, err := store.CreateItem(ctx, ItemCreate{
		UserID:       userID,
		Type:         "text",
		Metadata:     meta,
		Ciphertext:   []byte("c"),
		PayloadNonce: []byte("n"),
		EncDEK:       []byte("e"),
		DekNonce:     []byte("dn"),
	})
	if err != nil {
		t.Fatalf("create item: %v", err)
	}

	list, err := store.ListItems(ctx, userID)
	if err != nil {
		t.Fatalf("list items: %v", err)
	}
	if len(list) != 1 || list[0].ID != itemID {
		t.Fatalf("list mismatch")
	}

	item, err := store.GetItem(ctx, userID, itemID)
	if err != nil {
		t.Fatalf("get item: %v", err)
	}
	if item.ID != itemID || item.UserID != userID {
		t.Fatalf("item mismatch")
	}

	if err := store.DeleteItem(ctx, userID, itemID); err != nil {
		t.Fatalf("delete item: %v", err)
	}
	_, err = store.GetItem(ctx, userID, itemID)
	if err == nil {
		t.Fatalf("expected not found")
	}
}

func setupSchema(ctx context.Context, store *Store) error {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		return err
	}
	downPath := filepath.Join(root, "migrations", "001_init.down.sql")
	upPath := filepath.Join(root, "migrations", "001_init.up.sql")
	if err := runSQLFile(ctx, store.pool, downPath); err != nil {
		return err
	}
	return runSQLFile(ctx, store.pool, upPath)
}

func runSQLFile(ctx context.Context, pool *pgxpool.Pool, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	parts := strings.Split(string(data), ";")
	for _, p := range parts {
		stmt := strings.TrimSpace(p)
		if stmt == "" {
			continue
		}
		if _, err := pool.Exec(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}
