// Package storage provides Postgres persistence.
package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned when a record does not exist.
var ErrNotFound = errors.New("not found")

// Store wraps a pgx pool.
type Store struct {
	pool *pgxpool.Pool
}

// StoreAPI defines storage operations used by handlers.
type StoreAPI interface {
	CreateUser(ctx context.Context, username, passwordHash string) (string, error)
	GetUserByUsername(ctx context.Context, username string) (string, string, string, error)
	CreateItem(ctx context.Context, userID, typ string, metadata json.RawMessage, ciphertext, payloadNonce, encDEK, dekNonce []byte) (string, error)
	ListItems(ctx context.Context, userID string) ([]ItemMeta, error)
	GetItem(ctx context.Context, userID, itemID string) (ItemFull, error)
	DeleteItem(ctx context.Context, userID, itemID string) error
	Close()
}

// ItemMeta stores item metadata returned in list.
type ItemMeta struct {
	ID        string
	Type      string
	Metadata  json.RawMessage
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ItemFull stores full item data from storage.
type ItemFull struct {
	ID           string
	UserID       string
	Type         string
	Metadata     json.RawMessage
	Ciphertext   []byte
	PayloadNonce []byte
	EncDEK       []byte
	DekNonce     []byte
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// NewStore creates a new Store.
func NewStore(ctx context.Context, databaseURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}
	if err = pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping db: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close closes the underlying pool.
func (s *Store) Close() {
	if s.pool != nil {
		s.pool.Close()
	}
}

// CreateUser inserts a new user.
func (s *Store) CreateUser(ctx context.Context, username, passwordHash string) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx, `
        insert into users (username, password_hash, created_at)
        values ($1, $2, now())
        returning id
    `, username, passwordHash).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create user: %w", err)
	}
	return id, nil
}

// GetUserByUsername returns a user by username.
func (s *Store) GetUserByUsername(ctx context.Context, username string) (string, string, string, error) {
	var id string
	var user string
	var hash string
	err := s.pool.QueryRow(ctx, `
        select id, username, password_hash
        from users
        where username = $1
    `, username).Scan(&id, &user, &hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", "", ErrNotFound
		}
		return "", "", "", fmt.Errorf("get user: %w", err)
	}
	return id, user, hash, nil
}

// CreateItem inserts a new item.
func (s *Store) CreateItem(ctx context.Context, userID, typ string, metadata json.RawMessage, ciphertext, payloadNonce, encDEK, dekNonce []byte) (string, error) {
	if len(metadata) == 0 {
		metadata = json.RawMessage(`{}`)
	}
	metaText := string(metadata)
	var id string
	err := s.pool.QueryRow(ctx, `
        insert into items (user_id, type, metadata, ciphertext, payload_nonce, enc_dek, dek_nonce, created_at, updated_at)
        values ($1, $2, $3::jsonb, $4, $5, $6, $7, now(), now())
        returning id
    `, userID, typ, metaText, ciphertext, payloadNonce, encDEK, dekNonce).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create item: %w", err)
	}
	return id, nil
}

// ListItems returns metadata list for a user.
func (s *Store) ListItems(ctx context.Context, userID string) ([]ItemMeta, error) {
	rows, err := s.pool.Query(ctx, `
        select id, type, metadata, created_at, updated_at
        from items
        where user_id = $1
        order by created_at desc
    `, userID)
	if err != nil {
		return nil, fmt.Errorf("list items: %w", err)
	}
	defer rows.Close()

	var items []ItemMeta
	for rows.Next() {
		var item ItemMeta
		if err := rows.Scan(&item.ID, &item.Type, &item.Metadata, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan item: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}
	return items, nil
}

// GetItem returns a single item for a user.
func (s *Store) GetItem(ctx context.Context, userID, itemID string) (ItemFull, error) {
	var item ItemFull
	err := s.pool.QueryRow(ctx, `
        select id, user_id, type, metadata, ciphertext, payload_nonce, enc_dek, dek_nonce, created_at, updated_at
        from items
        where id = $1 and user_id = $2
    `, itemID, userID).Scan(
		&item.ID,
		&item.UserID,
		&item.Type,
		&item.Metadata,
		&item.Ciphertext,
		&item.PayloadNonce,
		&item.EncDEK,
		&item.DekNonce,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ItemFull{}, ErrNotFound
		}
		return ItemFull{}, fmt.Errorf("get item: %w", err)
	}
	return item, nil
}

// DeleteItem removes an item for a user.
func (s *Store) DeleteItem(ctx context.Context, userID, itemID string) error {
	tag, err := s.pool.Exec(ctx, `
        delete from items
        where id = $1 and user_id = $2
    `, itemID, userID)
	if err != nil {
		return fmt.Errorf("delete item: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
