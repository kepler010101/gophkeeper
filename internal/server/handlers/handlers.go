// Package handlers defines HTTP API.
package handlers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"gophkeeper/internal/auth"
	"gophkeeper/internal/crypto"
	"gophkeeper/internal/server/config"
	"gophkeeper/internal/server/storage"
)

type server struct {
	cfg       config.ServerConfig
	store     storage.StoreAPI
	masterKey []byte
}

// NewServer builds the HTTP handler.
func NewServer(cfg config.ServerConfig, store storage.StoreAPI, masterKey []byte) http.Handler {
	s := &server{cfg: cfg, store: store, masterKey: masterKey}
	r := chi.NewRouter()

	r.Post("/api/v1/auth/register", s.handleRegister)
	r.Post("/api/v1/auth/login", s.handleLogin)

	r.Route("/api/v1/items", func(r chi.Router) {
		r.Use(s.authMiddleware)
		r.Post("/", s.handleCreateItem)
		r.Get("/", s.handleListItems)
		r.Get("/{id}", s.handleGetItem)
		r.Delete("/{id}", s.handleDeleteItem)
	})

	return r
}

func (s *server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if strings.TrimSpace(req.Username) == "" || strings.TrimSpace(req.Password) == "" {
		writeError(w, http.StatusBadRequest, "missing fields")
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "hash failed")
		return
	}
	_, err = s.store.CreateUser(r.Context(), req.Username, hash)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "create user failed")
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if strings.TrimSpace(req.Username) == "" || strings.TrimSpace(req.Password) == "" {
		writeError(w, http.StatusBadRequest, "missing fields")
		return
	}
	id, _, hash, err := s.store.GetUserByUsername(r.Context(), req.Username)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		writeError(w, http.StatusInternalServerError, "get user failed")
		return
	}
	if !auth.VerifyPassword(hash, req.Password) {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	token, err := auth.GenerateJWT(id, s.cfg.JWTSecret, 24*time.Hour)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

func (s *server) handleCreateItem(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type          string          `json:"type"`
		Metadata      json.RawMessage `json:"metadata"`
		PayloadBase64 string          `json:"payload_base64"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if !validType(req.Type) {
		writeError(w, http.StatusBadRequest, "invalid type")
		return
	}
	if req.PayloadBase64 == "" {
		writeError(w, http.StatusBadRequest, "missing payload")
		return
	}
	payload, err := base64.StdEncoding.DecodeString(req.PayloadBase64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid base64")
		return
	}
	if int64(len(payload)) > s.cfg.PayloadMaxBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "payload too large")
		return
	}
	userID, ok := auth.UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing user")
		return
	}
	ciphertext, payloadNonce, encDEK, dekNonce, err := crypto.EncryptPayload(s.masterKey, payload)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encrypt error")
		return
	}
	id, err := s.store.CreateItem(r.Context(), userID, req.Type, req.Metadata, ciphertext, payloadNonce, encDEK, dekNonce)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "create item failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": id})
}

func (s *server) handleListItems(w http.ResponseWriter, r *http.Request) {
	userID, ok := auth.UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing user")
		return
	}
	items, err := s.store.ListItems(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list items failed")
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q != "" {
		q = strings.ToLower(q)
		filtered := make([]storage.ItemMeta, 0, len(items))
		for _, it := range items {
			if strings.Contains(strings.ToLower(string(it.Metadata)), q) {
				filtered = append(filtered, it)
			}
		}
		items = filtered
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *server) handleGetItem(w http.ResponseWriter, r *http.Request) {
	userID, ok := auth.UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing user")
		return
	}
	itemID := chi.URLParam(r, "id")
	if itemID == "" {
		writeError(w, http.StatusBadRequest, "missing id")
		return
	}
	item, err := s.store.GetItem(r.Context(), userID, itemID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get item failed")
		return
	}
	plaintext, err := crypto.DecryptPayload(s.masterKey, item.Ciphertext, item.PayloadNonce, item.EncDEK, item.DekNonce)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "decrypt error")
		return
	}
	resp := map[string]interface{}{
		"id":             item.ID,
		"type":           item.Type,
		"metadata":       item.Metadata,
		"payload_base64": base64.StdEncoding.EncodeToString(plaintext),
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *server) handleDeleteItem(w http.ResponseWriter, r *http.Request) {
	userID, ok := auth.UserIDFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing user")
		return
	}
	itemID := chi.URLParam(r, "id")
	if itemID == "" {
		writeError(w, http.StatusBadRequest, "missing id")
		return
	}
	err := s.store.DeleteItem(r.Context(), userID, itemID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "delete item failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := strings.TrimSpace(r.Header.Get("Authorization"))
		if h == "" || !strings.HasPrefix(h, "Bearer ") {
			writeError(w, http.StatusUnauthorized, "missing token")
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
		userID, err := auth.ValidateJWT(token, s.cfg.JWTSecret)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid token")
			return
		}
		ctx := auth.WithUserID(r.Context(), userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func validType(t string) bool {
	switch t {
	case "creds", "card", "text", "binary", "otp":
		return true
	default:
		return false
	}
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
