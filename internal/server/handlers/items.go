package handlers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"gophkeeper/internal/auth"
	"gophkeeper/internal/server/storage"
)

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
	id, err := s.svc.CreateItem(r.Context(), userID, req.Type, req.Metadata, payload)
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
	items, err := s.svc.ListItems(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list items failed")
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q != "" {
		q = strings.ToLower(q)
		filtered := make([]*storage.ItemMeta, 0, len(items))
		for _, it := range items {
			if it != nil && strings.Contains(strings.ToLower(string(it.Metadata)), q) {
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
	item, err := s.svc.GetItem(r.Context(), userID, itemID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get item failed")
		return
	}
	resp := map[string]any{
		"id":             item.ID,
		"type":           item.Type,
		"metadata":       item.Metadata,
		"payload_base64": base64.StdEncoding.EncodeToString(item.Payload),
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
	err := s.svc.DeleteItem(r.Context(), userID, itemID)
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

func validType(t string) bool {
	switch t {
	case "creds", "card", "text", "binary", "otp":
		return true
	default:
		return false
	}
}
