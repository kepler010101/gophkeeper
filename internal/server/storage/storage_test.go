package storage

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
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
	gotID, gotUser, gotHash, err := store.GetUserByUsername(ctx, "user1")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if gotID != userID || gotUser != "user1" || gotHash != "hash1" {
		t.Fatalf("user mismatch")
	}

	meta := json.RawMessage(`{"site":"example"}`)
	itemID, err := store.CreateItem(ctx, userID, "text", meta, []byte("c"), []byte("n"), []byte("e"), []byte("dn"))
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
	pool := store.pool
	stmts := []string{
		"drop table if exists items",
		"drop table if exists users",
		"create extension if not exists pgcrypto",
		`create table users (
            id uuid primary key default gen_random_uuid(),
            username text unique not null,
            password_hash text not null,
            created_at timestamptz not null default now()
        )`,
		`create table items (
            id uuid primary key default gen_random_uuid(),
            user_id uuid not null references users(id),
            type text not null,
            metadata jsonb not null default '{}'::jsonb,
            ciphertext bytea not null,
            payload_nonce bytea not null,
            enc_dek bytea not null,
            dek_nonce bytea not null,
            created_at timestamptz not null default now(),
            updated_at timestamptz not null default now()
        )`,
		"create index items_user_id_idx on items(user_id)",
		"create index items_created_at_idx on items(created_at)",
	}
	for _, stmt := range stmts {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}
