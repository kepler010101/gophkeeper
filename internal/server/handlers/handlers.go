package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"gophkeeper/internal/auth"
	"gophkeeper/internal/server/config"
	"gophkeeper/internal/server/service"
)

type server struct {
	cfg config.ServerConfig
	svc *service.Service
}

func NewServer(cfg config.ServerConfig, svc *service.Service) http.Handler {
	s := &server{cfg: cfg, svc: svc}
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

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
