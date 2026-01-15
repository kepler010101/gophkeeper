package service

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"gophkeeper/internal/auth"
	"gophkeeper/internal/crypto"
	"gophkeeper/internal/server/storage"
)

var ErrInvalidCredentials = errors.New("invalid credentials")

type Service struct {
	store     storage.StoreAPI
	masterKey []byte
	jwtSecret string
}

type ItemData struct {
	ID       string
	Type     string
	Metadata json.RawMessage
	Payload  []byte
}

func New(store storage.StoreAPI, masterKey []byte, jwtSecret string) *Service {
	return &Service{store: store, masterKey: masterKey, jwtSecret: jwtSecret}
}

func (s *Service) Register(ctx context.Context, username, password string) error {
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	_, err = s.store.CreateUser(ctx, username, hash)
	return err
}

func (s *Service) Login(ctx context.Context, username, password string) (string, error) {
	user, err := s.store.GetUserByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return "", ErrInvalidCredentials
		}
		return "", err
	}
	if !auth.VerifyPassword(user.PasswordHash, password) {
		return "", ErrInvalidCredentials
	}
	return auth.GenerateJWT(user.ID, s.jwtSecret, 24*time.Hour)
}

func (s *Service) CreateItem(ctx context.Context, userID, typ string, metadata json.RawMessage, payload []byte) (string, error) {
	ciphertext, payloadNonce, encDEK, dekNonce, err := crypto.EncryptPayload(s.masterKey, payload)
	if err != nil {
		return "", err
	}
	item := storage.ItemCreate{
		UserID:       userID,
		Type:         typ,
		Metadata:     metadata,
		Ciphertext:   ciphertext,
		PayloadNonce: payloadNonce,
		EncDEK:       encDEK,
		DekNonce:     dekNonce,
	}
	return s.store.CreateItem(ctx, item)
}

func (s *Service) ListItems(ctx context.Context, userID string) ([]*storage.ItemMeta, error) {
	return s.store.ListItems(ctx, userID)
}

func (s *Service) GetItem(ctx context.Context, userID, itemID string) (ItemData, error) {
	item, err := s.store.GetItem(ctx, userID, itemID)
	if err != nil {
		return ItemData{}, err
	}
	payload, err := crypto.DecryptPayload(s.masterKey, item.Ciphertext, item.PayloadNonce, item.EncDEK, item.DekNonce)
	if err != nil {
		return ItemData{}, err
	}
	return ItemData{
		ID:       item.ID,
		Type:     item.Type,
		Metadata: item.Metadata,
		Payload:  payload,
	}, nil
}

func (s *Service) DeleteItem(ctx context.Context, userID, itemID string) error {
	return s.store.DeleteItem(ctx, userID, itemID)
}
