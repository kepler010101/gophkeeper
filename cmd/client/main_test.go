package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gophkeeper/internal/client/cache"
)

type testItem struct {
	id        string
	typ       string
	metadata  json.RawMessage
	payload   []byte
	createdAt time.Time
	updatedAt time.Time
}

type testServer struct {
	token string
	items map[string]testItem
	next  int
}

func newTestServer() (*httptest.Server, *testServer) {
	ts := &testServer{
		token: "token123",
		items: make(map[string]testItem),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/register", ts.handleRegister)
	mux.HandleFunc("/api/v1/auth/login", ts.handleLogin)
	mux.HandleFunc("/api/v1/items", ts.handleItems)
	mux.HandleFunc("/api/v1/items/", ts.handleItemByID)
	return httptest.NewServer(mux), ts
}

func (s *testServer) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Username == "" || req.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *testServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"token": s.token})
}

func (s *testServer) authOK(r *http.Request) bool {
	return r.Header.Get("Authorization") == "Bearer "+s.token
}

func (s *testServer) handleItems(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodPost:
		var req struct {
			Type          string          `json:"type"`
			Metadata      json.RawMessage `json:"metadata"`
			PayloadBase64 string          `json:"payload_base64"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		payload, err := base64.StdEncoding.DecodeString(req.PayloadBase64)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		s.next++
		id := fmt.Sprintf("i%d", s.next)
		now := time.Now().UTC()
		s.items[id] = testItem{id: id, typ: req.Type, metadata: req.Metadata, payload: payload, createdAt: now, updatedAt: now}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"id": id})
	case http.MethodGet:
		type meta struct {
			ID        string          `json:"id"`
			Type      string          `json:"type"`
			Metadata  json.RawMessage `json:"metadata"`
			CreatedAt time.Time       `json:"created_at"`
			UpdatedAt time.Time       `json:"updated_at"`
		}
		out := []meta{}
		for _, it := range s.items {
			out = append(out, meta{
				ID:        it.id,
				Type:      it.typ,
				Metadata:  it.metadata,
				CreatedAt: it.createdAt,
				UpdatedAt: it.updatedAt,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *testServer) handleItemByID(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/items/")
	it, ok := s.items[id]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	switch r.Method {
	case http.MethodGet:
		resp := map[string]interface{}{
			"id":             it.id,
			"type":           it.typ,
			"metadata":       it.metadata,
			"payload_base64": base64.StdEncoding.EncodeToString(it.payload),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	case http.MethodDelete:
		delete(s.items, id)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func TestCLIFlow(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GOPHKEEPER_HOME", dir)

	server, ts := newTestServer()
	defer server.Close()

	runRegister([]string{"--username", "u1", "--password", "p1", "--server", server.URL})
	cfg, err := cache.LoadConfig()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.ServerURL != server.URL {
		t.Fatalf("server url")
	}

	runLogin([]string{"--username", "u1", "--password", "p1", "--server", server.URL})
	cfg, err = cache.LoadConfig()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Token == "" {
		t.Fatalf("missing token")
	}

	runPut([]string{"--type", "text", "--meta", "k=v", "--data", "hello", "--server", server.URL})
	if len(ts.items) != 1 {
		t.Fatalf("item not created")
	}
	filePath := filepath.Join(dir, "in.bin")
	if err := os.WriteFile(filePath, []byte("file"), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	runPut([]string{"--type", "binary", "--meta", "n=v", "--file", filePath, "--server", server.URL})
	runPut([]string{"--type", "otp", "--meta", "t=otp", "--data", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "--server", server.URL})
	if len(ts.items) != 3 {
		t.Fatalf("file item not created")
	}

	runList([]string{"--server", server.URL})
	list, err := cache.CacheListItems()
	if err != nil {
		t.Fatalf("cache list: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("cache size")
	}

	runSync([]string{"--server", server.URL})

	var id string
	var otpID string
	for k, it := range ts.items {
		if string(it.payload) == "hello" {
			id = k
		}
		if it.typ == "otp" {
			otpID = k
		}
	}
	if id == "" {
		t.Fatalf("id not found")
	}
	if otpID == "" {
		t.Fatalf("otp id not found")
	}

	payload, _, err := cache.CacheGetItem(id)
	if err != nil {
		t.Fatalf("cache get: %v", err)
	}
	if string(payload) != "hello" {
		t.Fatalf("cache payload mismatch")
	}

	code := captureStdout(func() {
		runOTP([]string{"--id", otpID, "--server", server.URL})
	})
	if len(code) != 6 {
		t.Fatalf("otp length")
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			t.Fatalf("otp not numeric")
		}
	}

	outPath := filepath.Join(dir, "out.bin")
	runGet([]string{"--id", id, "--out", outPath, "--server", server.URL})
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read out: %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("payload mismatch")
	}

	runDelete([]string{"--id", id, "--server", server.URL})
	if len(ts.items) != 2 {
		t.Fatalf("expected two items left")
	}
	for k := range ts.items {
		runDelete([]string{"--id", k, "--server", server.URL})
	}
	if len(ts.items) != 0 {
		t.Fatalf("items not deleted")
	}
}

func TestCLIListOffline(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GOPHKEEPER_HOME", dir)
	meta := cache.CachedMeta{ID: "id1", Type: "text", UpdatedAt: time.Now().UTC()}
	if err := cache.CachePutItem("id1", []byte("x"), meta); err != nil {
		t.Fatalf("cache put: %v", err)
	}
	cfg := cache.Config{ServerURL: "http://127.0.0.1:1", Token: "t"}
	if err := cache.SaveConfig(cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	runList([]string{})
}

func TestCLIGetOffline(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GOPHKEEPER_HOME", dir)
	meta := cache.CachedMeta{ID: "id1", Type: "text", UpdatedAt: time.Now().UTC()}
	if err := cache.CachePutItem("id1", []byte("x"), meta); err != nil {
		t.Fatalf("cache put: %v", err)
	}
	cfg := cache.Config{ServerURL: "http://127.0.0.1:1", Token: "t"}
	if err := cache.SaveConfig(cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	outPath := filepath.Join(dir, "out.bin")
	runGet([]string{"--id", "id1", "--out", outPath})
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read out: %v", err)
	}
	if string(data) != "x" {
		t.Fatalf("payload mismatch")
	}
}

func TestListNoTokenCache(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GOPHKEEPER_HOME", dir)
	meta := cache.CachedMeta{ID: "id1", Type: "text", UpdatedAt: time.Now().UTC()}
	if err := cache.CachePutItem("id1", []byte("x"), meta); err != nil {
		t.Fatalf("cache put: %v", err)
	}
	cfg := cache.Config{ServerURL: "http://127.0.0.1:1", Token: ""}
	if err := cache.SaveConfig(cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	runList([]string{})
}

func TestGetNoTokenCache(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GOPHKEEPER_HOME", dir)
	meta := cache.CachedMeta{ID: "id1", Type: "text", UpdatedAt: time.Now().UTC()}
	if err := cache.CachePutItem("id1", []byte("x"), meta); err != nil {
		t.Fatalf("cache put: %v", err)
	}
	cfg := cache.Config{ServerURL: "http://127.0.0.1:1", Token: ""}
	if err := cache.SaveConfig(cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	runGet([]string{"--id", "id1"})
}

func TestOTPFromCache(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GOPHKEEPER_HOME", dir)
	meta := cache.CachedMeta{ID: "id1", Type: "otp", UpdatedAt: time.Now().UTC()}
	if err := cache.CachePutItem("id1", []byte("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"), meta); err != nil {
		t.Fatalf("cache put: %v", err)
	}
	cfg := cache.Config{ServerURL: "http://127.0.0.1:1", Token: ""}
	if err := cache.SaveConfig(cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	out := captureStdout(func() {
		runOTP([]string{"--id", "id1"})
	})
	if len(out) != 6 {
		t.Fatalf("otp length")
	}
}

func TestRunRegisterMissing(t *testing.T) {
	expectFail(t, func() {
		runRegister([]string{"--username", "u"})
	})
}

func TestRunLoginMissing(t *testing.T) {
	expectFail(t, func() {
		runLogin([]string{"--password", "p"})
	})
}

func TestRunPutErrors(t *testing.T) {
	expectFail(t, func() {
		runPut([]string{})
	})
	expectFail(t, func() {
		runPut([]string{"--type", "bad", "--data", "x"})
	})
	expectFail(t, func() {
		runPut([]string{"--type", "text"})
	})
	expectFail(t, func() {
		runPut([]string{"--type", "text", "--meta", "a", "--data", "x"})
	})

	dir := t.TempDir()
	t.Setenv("GOPHKEEPER_HOME", dir)
	if err := cache.SaveConfig(cache.Config{ServerURL: "http://127.0.0.1:1", Token: ""}); err != nil {
		t.Fatalf("save config: %v", err)
	}
	expectFail(t, func() {
		runPut([]string{"--type", "text", "--data", "x"})
	})
}

func TestRunGetDeleteMissingID(t *testing.T) {
	expectFail(t, func() {
		runGet([]string{})
	})
	expectFail(t, func() {
		runDelete([]string{})
	})
}

func TestRunOTPNoID(t *testing.T) {
	expectFail(t, func() {
		runOTP([]string{})
	})
}

func TestRunListEmptyCache(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GOPHKEEPER_HOME", dir)
	if err := cache.SaveConfig(cache.Config{ServerURL: "http://127.0.0.1:1", Token: ""}); err != nil {
		t.Fatalf("save config: %v", err)
	}
	expectFail(t, func() {
		runList([]string{})
	})
}

func TestRunGetCacheMiss(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GOPHKEEPER_HOME", dir)
	if err := cache.SaveConfig(cache.Config{ServerURL: "http://127.0.0.1:1", Token: ""}); err != nil {
		t.Fatalf("save config: %v", err)
	}
	expectFail(t, func() {
		runGet([]string{"--id", "nope"})
	})
}

func TestRunConfigError(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GOPHKEEPER_HOME", dir)
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("{"), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	expectFail(t, func() {
		runRegister([]string{"--username", "u", "--password", "p"})
	})
}

func TestRunSaveConfigError(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "notdir")
	if err := os.WriteFile(filePath, []byte("x"), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	t.Setenv("GOPHKEEPER_HOME", filePath)
	expectFail(t, func() {
		runRegister([]string{"--username", "u", "--password", "p", "--server", "http://127.0.0.1:1"})
	})
}

func TestRunLoginInvalidResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth/login" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	dir := t.TempDir()
	t.Setenv("GOPHKEEPER_HOME", dir)
	expectFail(t, func() {
		runLogin([]string{"--username", "u", "--password", "p", "--server", ts.URL})
	})
}

func TestRunPutInvalidResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/items" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	dir := t.TempDir()
	t.Setenv("GOPHKEEPER_HOME", dir)
	if err := cache.SaveConfig(cache.Config{ServerURL: ts.URL, Token: "t"}); err != nil {
		t.Fatalf("save config: %v", err)
	}
	expectFail(t, func() {
		runPut([]string{"--type", "text", "--data", "x", "--server", ts.URL})
	})
}

func TestRunListInvalidResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/items" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("bad"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	dir := t.TempDir()
	t.Setenv("GOPHKEEPER_HOME", dir)
	if err := cache.SaveConfig(cache.Config{ServerURL: ts.URL, Token: "t"}); err != nil {
		t.Fatalf("save config: %v", err)
	}
	expectFail(t, func() {
		runList([]string{"--server", ts.URL})
	})
}

func TestRunGetInvalidResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/items/") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	dir := t.TempDir()
	t.Setenv("GOPHKEEPER_HOME", dir)
	if err := cache.SaveConfig(cache.Config{ServerURL: ts.URL, Token: "t"}); err != nil {
		t.Fatalf("save config: %v", err)
	}
	expectFail(t, func() {
		runGet([]string{"--id", "id1", "--server", ts.URL})
	})
}

func TestRunDeleteInvalidResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/items/") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"error":"bad"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	dir := t.TempDir()
	t.Setenv("GOPHKEEPER_HOME", dir)
	if err := cache.SaveConfig(cache.Config{ServerURL: ts.URL, Token: "t"}); err != nil {
		t.Fatalf("save config: %v", err)
	}
	expectFail(t, func() {
		runDelete([]string{"--id", "id1", "--server", ts.URL})
	})
}

func TestRunRegisterOffline(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GOPHKEEPER_HOME", dir)
	expectFail(t, func() {
		runRegister([]string{"--username", "u", "--password", "p", "--server", "http://127.0.0.1:1"})
	})
}

func TestRunLoginOffline(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GOPHKEEPER_HOME", dir)
	expectFail(t, func() {
		runLogin([]string{"--username", "u", "--password", "p", "--server", "http://127.0.0.1:1"})
	})
}

func TestRunPutOffline(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GOPHKEEPER_HOME", dir)
	if err := cache.SaveConfig(cache.Config{ServerURL: "http://127.0.0.1:1", Token: "t"}); err != nil {
		t.Fatalf("save config: %v", err)
	}
	expectFail(t, func() {
		runPut([]string{"--type", "text", "--data", "x", "--server", "http://127.0.0.1:1"})
	})
}

func TestRunDeleteOffline(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GOPHKEEPER_HOME", dir)
	if err := cache.SaveConfig(cache.Config{ServerURL: "http://127.0.0.1:1", Token: "t"}); err != nil {
		t.Fatalf("save config: %v", err)
	}
	expectFail(t, func() {
		runDelete([]string{"--id", "id1", "--server", "http://127.0.0.1:1"})
	})
}

func TestRunSyncOffline(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GOPHKEEPER_HOME", dir)
	if err := cache.SaveConfig(cache.Config{ServerURL: "http://127.0.0.1:1", Token: "t"}); err != nil {
		t.Fatalf("save config: %v", err)
	}
	expectFail(t, func() {
		runSync([]string{"--server", "http://127.0.0.1:1"})
	})
}

func TestRunGetInvalidPayload(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/items/") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"payload_base64":"***"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	dir := t.TempDir()
	t.Setenv("GOPHKEEPER_HOME", dir)
	if err := cache.SaveConfig(cache.Config{ServerURL: ts.URL, Token: "t"}); err != nil {
		t.Fatalf("save config: %v", err)
	}
	expectFail(t, func() {
		runGet([]string{"--id", "id1", "--server", ts.URL})
	})
}

func TestRunOTPInvalidPayload(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/items/") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"payload_base64":"***"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	dir := t.TempDir()
	t.Setenv("GOPHKEEPER_HOME", dir)
	if err := cache.SaveConfig(cache.Config{ServerURL: ts.URL, Token: "t"}); err != nil {
		t.Fatalf("save config: %v", err)
	}
	expectFail(t, func() {
		runOTP([]string{"--id", "id1", "--server", ts.URL})
	})
}

func TestRunSyncInvalidPayload(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/items":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"id":"id1","type":"text","metadata":{},"updated_at":"2024-01-01T00:00:00Z"}]`))
		case strings.HasPrefix(r.URL.Path, "/api/v1/items/"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"payload_base64":"***"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	dir := t.TempDir()
	t.Setenv("GOPHKEEPER_HOME", dir)
	if err := cache.SaveConfig(cache.Config{ServerURL: ts.URL, Token: "t"}); err != nil {
		t.Fatalf("save config: %v", err)
	}
	expectFail(t, func() {
		runSync([]string{"--server", ts.URL})
	})
}

func TestMainUsage(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"client"}
	out := captureStdout(func() {
		main()
	})
	if !strings.Contains(string(out), "commands:") {
		t.Fatalf("usage not printed")
	}
}

func TestMainVersion(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"client", "--version"}
	out := captureStdout(func() {
		main()
	})
	if !strings.Contains(string(out), "gophkeeper version=") {
		t.Fatalf("version not printed")
	}
}

func TestFilterCached(t *testing.T) {
	items := []cache.CachedMeta{
		{ID: "1", Metadata: json.RawMessage(`{"site":"example"}`)},
		{ID: "2", Metadata: json.RawMessage(`{"note":"hello"}`)},
	}
	got := filterCached(items, "example")
	if len(got) != 1 || got[0].ID != "1" {
		t.Fatalf("filter mismatch")
	}
}

func TestOTPCode(t *testing.T) {
	secret := []byte("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	code, err := otpCode(secret, time.Unix(59, 0).UTC())
	if err != nil {
		t.Fatalf("otp error: %v", err)
	}
	if code != "287082" {
		t.Fatalf("unexpected code: %s", code)
	}
}

func TestOTPCodeEmpty(t *testing.T) {
	_, err := otpCode([]byte(" "), time.Now().UTC())
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestParseMeta(t *testing.T) {
	data, err := parseMeta("a=b,c=d")
	if err != nil {
		t.Fatalf("meta error: %v", err)
	}
	if !strings.Contains(string(data), "\"a\"") || !strings.Contains(string(data), "\"b\"") {
		t.Fatalf("unexpected meta")
	}
}

func TestParseMetaInvalid(t *testing.T) {
	_, err := parseMeta("a")
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestParseMetaEmpty(t *testing.T) {
	data, err := parseMeta("")
	if err != nil {
		t.Fatalf("meta error: %v", err)
	}
	if strings.TrimSpace(string(data)) != "{}" {
		t.Fatalf("unexpected meta")
	}
}

func TestReadAPIError(t *testing.T) {
	msg := readAPIError([]byte(`{"error":"bad"}`))
	if msg != "bad" {
		t.Fatalf("unexpected msg")
	}
	msg = readAPIError([]byte(""))
	if msg != "unknown error" {
		t.Fatalf("unexpected empty msg")
	}
	msg = readAPIError([]byte("plain"))
	if msg != "plain" {
		t.Fatalf("unexpected plain msg")
	}
}

func TestIsOfflineErr(t *testing.T) {
	if !isOfflineErr(errors.New("x509: certificate signed by unknown authority")) {
		t.Fatalf("expected true")
	}
	if !isOfflineErr(fakeNetErr{}) {
		t.Fatalf("expected true")
	}
	if !isOfflineErr(&url.Error{Err: errors.New("net")}) {
		t.Fatalf("expected true")
	}
}

func TestDecodeOTPSecret(t *testing.T) {
	secret := decodeOTPSecret([]byte("GEZDGNBVGY3TQOJQ"))
	if len(secret) == 0 {
		t.Fatalf("expected decoded secret")
	}
	raw := decodeOTPSecret([]byte("rawsecret"))
	raw = decodeOTPSecret([]byte("rawsecret!"))
	if string(raw) != "RAWSECRET!" {
		t.Fatalf("unexpected raw secret")
	}
}

func TestValidType(t *testing.T) {
	if !validType("otp") {
		t.Fatalf("expected true")
	}
	if validType("bad") {
		t.Fatalf("expected false")
	}
}

func TestResolveServerURL(t *testing.T) {
	cfg := cache.Config{}
	_, urlStr, changed := resolveServerURL(cfg, "")
	if changed || urlStr != "https://localhost:8443" {
		t.Fatalf("unexpected default url")
	}
	cfg = cache.Config{ServerURL: "https://old"}
	_, urlStr, changed = resolveServerURL(cfg, "")
	if changed || urlStr != "https://old" {
		t.Fatalf("unexpected stored url")
	}
	cfg = cache.Config{ServerURL: "https://old"}
	cfg, urlStr, changed = resolveServerURL(cfg, "https://new")
	if !changed || cfg.ServerURL != "https://new" || urlStr != "https://new" {
		t.Fatalf("unexpected override")
	}
}

func TestDoRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method")
		}
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("auth header")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	status, body, err := doRequest(http.MethodPost, ts.URL, map[string]string{"a": "b"}, "token", false)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("status")
	}
	if !strings.Contains(string(body), "ok") {
		t.Fatalf("body")
	}
}

func TestDoRequestInsecure(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	status, _, err := doRequest(http.MethodGet, ts.URL, nil, "", true)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("status")
	}
}

func TestWritePayload(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.bin")
	out := captureStdout(func() {
		writePayload([]byte("hi"), outPath)
	})
	if out != outPath {
		t.Fatalf("unexpected output")
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read out: %v", err)
	}
	if string(data) != "hi" {
		t.Fatalf("payload mismatch")
	}

	out = captureStdout(func() {
		writePayload([]byte("hi"), "")
	})
	if out != "aGk=" {
		t.Fatalf("unexpected output")
	}
}

type fakeNetErr struct{}

func (fakeNetErr) Error() string   { return "net" }
func (fakeNetErr) Timeout() bool   { return true }
func (fakeNetErr) Temporary() bool { return true }

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

func expectFail(t *testing.T, fn func()) {
	t.Helper()
	t.Setenv("GOPHKEEPER_TESTING", "1")
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected fail")
		}
	}()
	fn()
}
