package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"gophkeeper/internal/auth"
	"gophkeeper/internal/server/config"
	"gophkeeper/internal/server/service"
	"gophkeeper/internal/server/storage"
)

type mockStore struct {
	userSeq   int
	itemSeq   int
	users     map[string]userRow
	items     map[string]storage.ItemFull
	userItems map[string][]string
}

type userRow struct {
	id       string
	username string
	hash     string
}

type errStore struct {
	createUserErr error
	getUserErr    error
	createItemErr error
	getItem       storage.ItemFull
	getItemErr    error
	deleteItemErr error
}

func (e *errStore) Close() {}

func (e *errStore) CreateUser(ctx context.Context, username, passwordHash string) (string, error) {
	if e.createUserErr != nil {
		return "", e.createUserErr
	}
	return "u1", nil
}

func (e *errStore) GetUserByUsername(ctx context.Context, username string) (*storage.User, error) {
	if e.getUserErr != nil {
		return nil, e.getUserErr
	}
	return &storage.User{ID: "u1", Username: username, PasswordHash: "hash"}, nil
}

func (e *errStore) CreateItem(ctx context.Context, item storage.ItemCreate) (string, error) {
	if e.createItemErr != nil {
		return "", e.createItemErr
	}
	return "i1", nil
}

func (e *errStore) ListItems(ctx context.Context, userID string) ([]*storage.ItemMeta, error) {
	return nil, nil
}

func (e *errStore) GetItem(ctx context.Context, userID, itemID string) (*storage.ItemFull, error) {
	if e.getItemErr != nil {
		return nil, e.getItemErr
	}
	return &e.getItem, nil
}

func (e *errStore) DeleteItem(ctx context.Context, userID, itemID string) error {
	return e.deleteItemErr
}

func newMockStore() *mockStore {
	return &mockStore{
		users:     make(map[string]userRow),
		items:     make(map[string]storage.ItemFull),
		userItems: make(map[string][]string),
	}
}

func (m *mockStore) Close() {}

func (m *mockStore) CreateUser(ctx context.Context, username, passwordHash string) (string, error) {
	m.userSeq++
	id := "u" + strconv.Itoa(m.userSeq)
	m.users[username] = userRow{id: id, username: username, hash: passwordHash}
	return id, nil
}

func (m *mockStore) GetUserByUsername(ctx context.Context, username string) (*storage.User, error) {
	u, ok := m.users[username]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return &storage.User{ID: u.id, Username: u.username, PasswordHash: u.hash}, nil
}

func (m *mockStore) CreateItem(ctx context.Context, item storage.ItemCreate) (string, error) {
	m.itemSeq++
	id := "i" + strconv.Itoa(m.itemSeq)
	fullItem := storage.ItemFull{
		ID:           id,
		UserID:       item.UserID,
		Type:         item.Type,
		Metadata:     item.Metadata,
		Ciphertext:   item.Ciphertext,
		PayloadNonce: item.PayloadNonce,
		EncDEK:       item.EncDEK,
		DekNonce:     item.DekNonce,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}
	m.items[id] = fullItem
	m.userItems[item.UserID] = append(m.userItems[item.UserID], id)
	return id, nil
}

func (m *mockStore) ListItems(ctx context.Context, userID string) ([]*storage.ItemMeta, error) {
	ids := m.userItems[userID]
	items := make([]*storage.ItemMeta, 0, len(ids))
	for _, id := range ids {
		item := m.items[id]
		items = append(items, &storage.ItemMeta{
			ID:        item.ID,
			Type:      item.Type,
			Metadata:  item.Metadata,
			CreatedAt: item.CreatedAt,
			UpdatedAt: item.UpdatedAt,
		})
	}
	return items, nil
}

func (m *mockStore) GetItem(ctx context.Context, userID, itemID string) (*storage.ItemFull, error) {
	item, ok := m.items[itemID]
	if !ok || item.UserID != userID {
		return nil, storage.ErrNotFound
	}
	return &item, nil
}

func (m *mockStore) DeleteItem(ctx context.Context, userID, itemID string) error {
	item, ok := m.items[itemID]
	if !ok || item.UserID != userID {
		return storage.ErrNotFound
	}
	delete(m.items, itemID)
	ids := m.userItems[userID]
	next := ids[:0]
	for _, id := range ids {
		if id != itemID {
			next = append(next, id)
		}
	}
	m.userItems[userID] = next
	return nil
}

func newTestServer(t *testing.T, payloadMax int64) (*httptest.Server, *mockStore) {
	t.Helper()
	store := newMockStore()
	cfg := config.ServerConfig{
		JWTSecret:       "secretsecretsecretsecretsecret12",
		PayloadMaxBytes: payloadMax,
	}
	masterKey := bytes.Repeat([]byte{1}, 32)
	svc := service.New(store, masterKey, cfg.JWTSecret)
	handler := NewServer(cfg, svc)
	return httptest.NewServer(handler), store
}

func newTestServerWithStore(t *testing.T, store storage.StoreAPI) *httptest.Server {
	t.Helper()
	cfg := config.ServerConfig{
		JWTSecret:       "secretsecretsecretsecretsecret12",
		PayloadMaxBytes: 10 * 1024 * 1024,
	}
	masterKey := bytes.Repeat([]byte{1}, 32)
	svc := service.New(store, masterKey, cfg.JWTSecret)
	handler := NewServer(cfg, svc)
	return httptest.NewServer(handler)
}

func makeToken(t *testing.T, userID string) string {
	t.Helper()
	token, err := auth.GenerateJWT(userID, "secretsecretsecretsecretsecret12", time.Hour)
	if err != nil {
		t.Fatalf("token error: %v", err)
	}
	return token
}

func register(t *testing.T, ts *httptest.Server, username, password string) {
	t.Helper()
	body := map[string]string{"username": username, "password": password}
	b, _ := json.Marshal(body)
	res, err := http.Post(ts.URL+"/api/v1/auth/register", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("register request: %v", err)
	}
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("register status: %d", res.StatusCode)
	}
}

func login(t *testing.T, ts *httptest.Server, username, password string) string {
	t.Helper()
	body := map[string]string{"username": username, "password": password}
	b, _ := json.Marshal(body)
	res, err := http.Post(ts.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("login request: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login status: %d", res.StatusCode)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode login: %v", err)
	}
	if out.Token == "" {
		t.Fatalf("empty token")
	}
	return out.Token
}

func authReq(t *testing.T, method, url, token string, body interface{}) *http.Response {
	t.Helper()
	var r *http.Request
	if body != nil {
		b, _ := json.Marshal(body)
		r, _ = http.NewRequest(method, url, bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r, _ = http.NewRequest(method, url, nil)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	return res
}

func TestRegisterLogin(t *testing.T) {
	ts, _ := newTestServer(t, 10*1024*1024)
	defer ts.Close()
	register(t, ts, "user1", "pass1")
	_ = login(t, ts, "user1", "pass1")
}

func TestRegisterMissingFields(t *testing.T) {
	ts, _ := newTestServer(t, 10*1024*1024)
	defer ts.Close()
	body := map[string]string{"username": "u1", "password": ""}
	b, _ := json.Marshal(body)
	res, err := http.Post(ts.URL+"/api/v1/auth/register", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("register request: %v", err)
	}
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("register status: %d", res.StatusCode)
	}
}

func TestItemsFlow(t *testing.T) {
	ts, _ := newTestServer(t, 10*1024*1024)
	defer ts.Close()
	register(t, ts, "user1", "pass1")
	token := login(t, ts, "user1", "pass1")

	payload := base64.StdEncoding.EncodeToString([]byte("hello"))
	createBody := map[string]interface{}{
		"type":           "text",
		"metadata":       map[string]interface{}{"site": "example"},
		"payload_base64": payload,
	}
	res := authReq(t, http.MethodPost, ts.URL+"/api/v1/items", token, createBody)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("create status: %d", res.StatusCode)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(res.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if created.ID == "" {
		t.Fatalf("empty id")
	}

	res = authReq(t, http.MethodGet, ts.URL+"/api/v1/items", token, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("list status: %d", res.StatusCode)
	}
	var list []struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(res.Body).Decode(&list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("list size: %d", len(list))
	}

	res = authReq(t, http.MethodGet, ts.URL+"/api/v1/items?q=example", token, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("search status: %d", res.StatusCode)
	}
	if err := json.NewDecoder(res.Body).Decode(&list); err != nil {
		t.Fatalf("decode search: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("search size: %d", len(list))
	}

	res = authReq(t, http.MethodGet, ts.URL+"/api/v1/items?q=nomatch", token, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("search status: %d", res.StatusCode)
	}
	if err := json.NewDecoder(res.Body).Decode(&list); err != nil {
		t.Fatalf("decode search: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("search size: %d", len(list))
	}

	res = authReq(t, http.MethodGet, ts.URL+"/api/v1/items/"+created.ID, token, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("get status: %d", res.StatusCode)
	}
	var got struct {
		PayloadBase64 string `json:"payload_base64"`
	}
	if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if got.PayloadBase64 != payload {
		t.Fatalf("payload mismatch")
	}

	res = authReq(t, http.MethodDelete, ts.URL+"/api/v1/items/"+created.ID, token, nil)
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status: %d", res.StatusCode)
	}
}

func TestNoJWT(t *testing.T) {
	ts, _ := newTestServer(t, 10*1024*1024)
	defer ts.Close()
	res := authReq(t, http.MethodGet, ts.URL+"/api/v1/items", "", nil)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: %d", res.StatusCode)
	}
}

func TestCreateItemInvalidType(t *testing.T) {
	ts, _ := newTestServer(t, 10*1024*1024)
	defer ts.Close()
	register(t, ts, "user1", "pass1")
	token := login(t, ts, "user1", "pass1")

	body := map[string]interface{}{
		"type":           "bad",
		"metadata":       map[string]interface{}{"a": 1},
		"payload_base64": base64.StdEncoding.EncodeToString([]byte("data")),
	}
	res := authReq(t, http.MethodPost, ts.URL+"/api/v1/items", token, body)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: %d", res.StatusCode)
	}
}

func TestCreateItemTooLarge(t *testing.T) {
	ts, _ := newTestServer(t, 2)
	defer ts.Close()
	register(t, ts, "user1", "pass1")
	token := login(t, ts, "user1", "pass1")

	body := map[string]interface{}{
		"type":           "text",
		"metadata":       map[string]interface{}{"a": 1},
		"payload_base64": base64.StdEncoding.EncodeToString([]byte("abc")),
	}
	res := authReq(t, http.MethodPost, ts.URL+"/api/v1/items", token, body)
	if res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status: %d", res.StatusCode)
	}
}

func TestLoginInvalidPassword(t *testing.T) {
	ts, _ := newTestServer(t, 10*1024*1024)
	defer ts.Close()
	register(t, ts, "user1", "pass1")
	body := map[string]string{"username": "user1", "password": "wrong"}
	b, _ := json.Marshal(body)
	res, err := http.Post(ts.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("login request: %v", err)
	}
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("login status: %d", res.StatusCode)
	}
}

func TestLoginInvalidJSON(t *testing.T) {
	ts, _ := newTestServer(t, 10*1024*1024)
	defer ts.Close()
	res, err := http.Post(ts.URL+"/api/v1/auth/login", "application/json", bytes.NewReader([]byte("{")))
	if err != nil {
		t.Fatalf("login request: %v", err)
	}
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("login status: %d", res.StatusCode)
	}
}

func TestRegisterStoreError(t *testing.T) {
	ts := newTestServerWithStore(t, &errStore{createUserErr: errors.New("db")})
	defer ts.Close()
	body := map[string]string{"username": "u1", "password": "p1"}
	b, _ := json.Marshal(body)
	res, err := http.Post(ts.URL+"/api/v1/auth/register", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("register request: %v", err)
	}
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("register status: %d", res.StatusCode)
	}
}

func TestLoginStoreError(t *testing.T) {
	ts := newTestServerWithStore(t, &errStore{getUserErr: errors.New("db")})
	defer ts.Close()
	body := map[string]string{"username": "u1", "password": "p1"}
	b, _ := json.Marshal(body)
	res, err := http.Post(ts.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("login request: %v", err)
	}
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("login status: %d", res.StatusCode)
	}
}

func TestCreateItemInvalidBase64(t *testing.T) {
	ts, _ := newTestServer(t, 10*1024*1024)
	defer ts.Close()
	register(t, ts, "user1", "pass1")
	token := login(t, ts, "user1", "pass1")

	body := map[string]interface{}{
		"type":           "text",
		"metadata":       map[string]interface{}{"a": 1},
		"payload_base64": "not-base64",
	}
	res := authReq(t, http.MethodPost, ts.URL+"/api/v1/items", token, body)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: %d", res.StatusCode)
	}
}

func TestCreateItemMissingPayload(t *testing.T) {
	ts, _ := newTestServer(t, 10*1024*1024)
	defer ts.Close()
	register(t, ts, "user1", "pass1")
	token := login(t, ts, "user1", "pass1")

	body := map[string]interface{}{
		"type":     "text",
		"metadata": map[string]interface{}{"a": 1},
	}
	res := authReq(t, http.MethodPost, ts.URL+"/api/v1/items", token, body)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: %d", res.StatusCode)
	}
}

func TestCreateItemStoreError(t *testing.T) {
	ts := newTestServerWithStore(t, &errStore{createItemErr: errors.New("db")})
	defer ts.Close()
	token := makeToken(t, "u1")
	body := map[string]interface{}{
		"type":           "text",
		"metadata":       map[string]interface{}{"a": 1},
		"payload_base64": base64.StdEncoding.EncodeToString([]byte("data")),
	}
	res := authReq(t, http.MethodPost, ts.URL+"/api/v1/items", token, body)
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status: %d", res.StatusCode)
	}
}

func TestRegisterInvalidJSON(t *testing.T) {
	ts, _ := newTestServer(t, 10*1024*1024)
	defer ts.Close()
	res, err := http.Post(ts.URL+"/api/v1/auth/register", "application/json", bytes.NewReader([]byte("{")))
	if err != nil {
		t.Fatalf("register request: %v", err)
	}
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("register status: %d", res.StatusCode)
	}
}

func TestGetDeleteNotFound(t *testing.T) {
	ts, _ := newTestServer(t, 10*1024*1024)
	defer ts.Close()
	register(t, ts, "user1", "pass1")
	token := login(t, ts, "user1", "pass1")

	res := authReq(t, http.MethodGet, ts.URL+"/api/v1/items/nope", token, nil)
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("get status: %d", res.StatusCode)
	}
	res = authReq(t, http.MethodDelete, ts.URL+"/api/v1/items/nope", token, nil)
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("delete status: %d", res.StatusCode)
	}
}

func TestGetItemDecryptError(t *testing.T) {
	store := &errStore{
		getItem: storage.ItemFull{
			ID:           "i1",
			UserID:       "u1",
			Type:         "text",
			Ciphertext:   bytes.Repeat([]byte{1}, 16),
			PayloadNonce: bytes.Repeat([]byte{2}, 12),
			EncDEK:       bytes.Repeat([]byte{3}, 16),
			DekNonce:     bytes.Repeat([]byte{4}, 12),
		},
	}
	ts := newTestServerWithStore(t, store)
	defer ts.Close()
	token := makeToken(t, "u1")
	res := authReq(t, http.MethodGet, ts.URL+"/api/v1/items/i1", token, nil)
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status: %d", res.StatusCode)
	}
}

func TestDeleteItemStoreError(t *testing.T) {
	ts := newTestServerWithStore(t, &errStore{deleteItemErr: errors.New("db")})
	defer ts.Close()
	token := makeToken(t, "u1")
	res := authReq(t, http.MethodDelete, ts.URL+"/api/v1/items/i1", token, nil)
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status: %d", res.StatusCode)
	}
}

func TestInvalidToken(t *testing.T) {
	ts, _ := newTestServer(t, 10*1024*1024)
	defer ts.Close()
	res := authReq(t, http.MethodGet, ts.URL+"/api/v1/items", "bad.token.here", nil)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: %d", res.StatusCode)
	}
}

func TestJWTExpired(t *testing.T) {
	secret := "secretsecretsecretsecretsecret12"
	token, err := auth.GenerateJWT("user1", secret, -time.Minute)
	if err != nil {
		t.Fatalf("generate error: %v", err)
	}
	_, err = auth.ValidateJWT(token, secret)
	if err == nil {
		t.Fatalf("expected error")
	}
}
