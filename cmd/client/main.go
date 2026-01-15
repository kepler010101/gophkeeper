package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"gophkeeper/internal/client/cache"
	"gophkeeper/internal/version"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println(version.String())
		return
	}
	if len(os.Args) < 2 || os.Args[1] == "--help" || os.Args[1] == "-h" {
		printUsage()
		return
	}
	switch os.Args[1] {
	case "register":
		runRegister(os.Args[2:])
	case "login":
		runLogin(os.Args[2:])
	case "put":
		runPut(os.Args[2:])
	case "list":
		runList(os.Args[2:])
	case "sync":
		runSync(os.Args[2:])
	case "get":
		runGet(os.Args[2:])
	case "otp":
		runOTP(os.Args[2:])
	case "delete":
		runDelete(os.Args[2:])
	default:
		printUsage()
	}
}

func printUsage() {
	fmt.Println("gophkeeper client")
	fmt.Println("commands:")
	fmt.Println("  register --username --password [--server] [--insecure]")
	fmt.Println("  login --username --password [--server] [--insecure]")
	fmt.Println("  put --type creds|card|text|binary|otp --meta key=value,... [--data \"...\"] [--file path] [--insecure] [--server]")
	fmt.Println("  list [--search value] [--insecure] [--server]")
	fmt.Println("  sync [--insecure] [--server]")
	fmt.Println("  get --id ID [--out path] [--insecure] [--server]")
	fmt.Println("  otp --id ID [--insecure] [--server]")
	fmt.Println("  delete --id ID [--insecure] [--server]")
}

func runRegister(args []string) {
	fs := newFlagSet("register")
	username := fs.String("username", "", "")
	password := fs.String("password", "", "")
	server := fs.String("server", "", "")
	insecure := fs.Bool("insecure", false, "")
	parseFlags(fs, args)

	if *username == "" || *password == "" {
		fail("missing username or password")
	}

	cfg, err := cache.LoadConfig()
	if err != nil {
		fail("config error: %v", err)
	}
	cfg, serverURL, cfgChanged := resolveServerURL(cfg, *server)
	if cfgChanged {
		if err := cache.SaveConfig(cfg); err != nil {
			fail("save config: %v", err)
		}
	}

	body := map[string]string{"username": *username, "password": *password}
	status, respBody, err := doRequest(http.MethodPost, serverURL+"/api/v1/auth/register", body, "", *insecure)
	if err != nil {
		if isOfflineErr(err) {
			fail("offline: read-only mode")
		}
		fail("request error: %v", err)
	}
	if status != http.StatusCreated {
		fail("register failed: %s", readAPIError(respBody))
	}
	fmt.Println("ok")
}

func runLogin(args []string) {
	fs := newFlagSet("login")
	username := fs.String("username", "", "")
	password := fs.String("password", "", "")
	server := fs.String("server", "", "")
	insecure := fs.Bool("insecure", false, "")
	parseFlags(fs, args)

	if *username == "" || *password == "" {
		fail("missing username or password")
	}

	cfg, err := cache.LoadConfig()
	if err != nil {
		fail("config error: %v", err)
	}
	cfg, serverURL, cfgChanged := resolveServerURL(cfg, *server)
	if cfgChanged {
		if err := cache.SaveConfig(cfg); err != nil {
			fail("save config: %v", err)
		}
	}

	body := map[string]string{"username": *username, "password": *password}
	status, respBody, err := doRequest(http.MethodPost, serverURL+"/api/v1/auth/login", body, "", *insecure)
	if err != nil {
		if isOfflineErr(err) {
			fail("offline: read-only mode")
		}
		fail("request error: %v", err)
	}
	if status != http.StatusOK {
		fail("login failed: %s", readAPIError(respBody))
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(respBody, &out); err != nil || out.Token == "" {
		fail("invalid login response")
	}
	cfg.Token = out.Token
	if err := cache.SaveConfig(cfg); err != nil {
		fail("save config: %v", err)
	}
	fmt.Println("ok")
}

func runPut(args []string) {
	fs := newFlagSet("put")
	typ := fs.String("type", "", "")
	metaStr := fs.String("meta", "", "")
	dataStr := fs.String("data", "", "")
	filePath := fs.String("file", "", "")
	server := fs.String("server", "", "")
	insecure := fs.Bool("insecure", false, "")
	parseFlags(fs, args)

	if *typ == "" {
		fail("missing type")
	}
	if !validType(*typ) {
		fail("invalid type")
	}
	var payload []byte
	var err error
	if *filePath != "" {
		payload, err = os.ReadFile(*filePath)
		if err != nil {
			fail("read file: %v", err)
		}
	} else if *dataStr != "" {
		payload = []byte(*dataStr)
	} else {
		fail("missing data or file")
	}
	metaJSON, err := parseMeta(*metaStr)
	if err != nil {
		fail("invalid meta")
	}

	cfg, err := cache.LoadConfig()
	if err != nil {
		fail("config error: %v", err)
	}
	cfg, serverURL, cfgChanged := resolveServerURL(cfg, *server)
	if cfgChanged {
		if err := cache.SaveConfig(cfg); err != nil {
			fail("save config: %v", err)
		}
	}
	if cfg.Token == "" {
		fail("not logged in")
	}

	body := map[string]interface{}{
		"type":           *typ,
		"metadata":       json.RawMessage(metaJSON),
		"payload_base64": base64.StdEncoding.EncodeToString(payload),
	}
	status, respBody, err := doRequest(http.MethodPost, serverURL+"/api/v1/items", body, cfg.Token, *insecure)
	if err != nil {
		if isOfflineErr(err) {
			fail("offline: read-only mode")
		}
		fail("request error: %v", err)
	}
	if status != http.StatusOK {
		fail("put failed: %s", readAPIError(respBody))
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(respBody, &out); err != nil || out.ID == "" {
		fail("invalid response")
	}
	fmt.Println(out.ID)
}

func runList(args []string) {
	fs := newFlagSet("list")
	search := fs.String("search", "", "")
	server := fs.String("server", "", "")
	insecure := fs.Bool("insecure", false, "")
	parseFlags(fs, args)

	cfg, err := cache.LoadConfig()
	if err != nil {
		fail("config error: %v", err)
	}
	cfg, serverURL, cfgChanged := resolveServerURL(cfg, *server)
	if cfgChanged {
		if err := cache.SaveConfig(cfg); err != nil {
			fail("save config: %v", err)
		}
	}
	if cfg.Token == "" {
		listFromCache(*search)
		return
	}

	urlStr := serverURL + "/api/v1/items"
	if strings.TrimSpace(*search) != "" {
		urlStr += "?q=" + url.QueryEscape(*search)
	}
	status, respBody, err := doRequest(http.MethodGet, urlStr, nil, cfg.Token, *insecure)
	if err != nil {
		if isOfflineErr(err) {
			listFromCache(*search)
			return
		}
		fail("request error: %v", err)
	}
	if status != http.StatusOK {
		fail("list failed: %s", readAPIError(respBody))
	}
	var items []cache.CachedMeta
	if err := json.Unmarshal(respBody, &items); err != nil {
		fail("invalid list response")
	}
	if strings.TrimSpace(*search) == "" {
		if err := saveCacheList(items); err != nil {
			fail("cache error: %v", err)
		}
	}
	printList(items)
}

func runSync(args []string) {
	fs := newFlagSet("sync")
	server := fs.String("server", "", "")
	insecure := fs.Bool("insecure", false, "")
	parseFlags(fs, args)

	cfg, err := cache.LoadConfig()
	if err != nil {
		fail("config error: %v", err)
	}
	cfg, serverURL, cfgChanged := resolveServerURL(cfg, *server)
	if cfgChanged {
		if err := cache.SaveConfig(cfg); err != nil {
			fail("save config: %v", err)
		}
	}
	if cfg.Token == "" {
		fail("not logged in")
	}

	status, respBody, err := doRequest(http.MethodGet, serverURL+"/api/v1/items", nil, cfg.Token, *insecure)
	if err != nil {
		if isOfflineErr(err) {
			fail("offline: read-only mode")
		}
		fail("request error: %v", err)
	}
	if status != http.StatusOK {
		fail("sync failed: %s", readAPIError(respBody))
	}
	var items []cache.CachedMeta
	if err := json.Unmarshal(respBody, &items); err != nil {
		fail("invalid list response")
	}

	metaByID := map[string]cache.CachedMeta{}
	for _, it := range items {
		metaByID[it.ID] = it
	}

	for _, it := range items {
		status, respBody, err = doRequest(http.MethodGet, serverURL+"/api/v1/items/"+url.PathEscape(it.ID), nil, cfg.Token, *insecure)
		if err != nil {
			if isOfflineErr(err) {
				fail("offline: read-only mode")
			}
			fail("request error: %v", err)
		}
		if status != http.StatusOK {
			fail("sync failed: %s", readAPIError(respBody))
		}
		var resp struct {
			ID            string          `json:"id"`
			Type          string          `json:"type"`
			Metadata      json.RawMessage `json:"metadata"`
			PayloadBase64 string          `json:"payload_base64"`
		}
		if err := json.Unmarshal(respBody, &resp); err != nil || resp.PayloadBase64 == "" {
			fail("invalid response")
		}
		payload, err := base64.StdEncoding.DecodeString(resp.PayloadBase64)
		if err != nil {
			fail("invalid payload")
		}
		meta := metaByID[it.ID]
		if meta.ID == "" {
			meta = cache.CachedMeta{ID: resp.ID, Type: resp.Type, Metadata: resp.Metadata, UpdatedAt: time.Now().UTC()}
		}
		if meta.Type == "" {
			meta.Type = resp.Type
		}
		if meta.Metadata == nil && len(resp.Metadata) > 0 {
			meta.Metadata = resp.Metadata
		}
		if meta.UpdatedAt.IsZero() {
			meta.UpdatedAt = time.Now().UTC()
		}
		if err := cache.CachePutItem(it.ID, payload, meta); err != nil {
			fail("cache error: %v", err)
		}
	}
	fmt.Println("ok")
}

func runGet(args []string) {
	fs := newFlagSet("get")
	id := fs.String("id", "", "")
	out := fs.String("out", "", "")
	server := fs.String("server", "", "")
	insecure := fs.Bool("insecure", false, "")
	parseFlags(fs, args)

	if *id == "" {
		fail("missing id")
	}
	cfg, err := cache.LoadConfig()
	if err != nil {
		fail("config error: %v", err)
	}
	cfg, serverURL, cfgChanged := resolveServerURL(cfg, *server)
	if cfgChanged {
		if err := cache.SaveConfig(cfg); err != nil {
			fail("save config: %v", err)
		}
	}

	if cfg.Token != "" {
		status, respBody, err := doRequest(http.MethodGet, serverURL+"/api/v1/items/"+url.PathEscape(*id), nil, cfg.Token, *insecure)
		if err == nil && status == http.StatusOK {
			var resp struct {
				ID            string          `json:"id"`
				Type          string          `json:"type"`
				Metadata      json.RawMessage `json:"metadata"`
				PayloadBase64 string          `json:"payload_base64"`
			}
			if err := json.Unmarshal(respBody, &resp); err != nil || resp.PayloadBase64 == "" {
				fail("invalid response")
			}
			payload, err := base64.StdEncoding.DecodeString(resp.PayloadBase64)
			if err != nil {
				fail("invalid payload")
			}
			meta := cache.CachedMeta{
				ID:        resp.ID,
				Type:      resp.Type,
				Metadata:  resp.Metadata,
				UpdatedAt: time.Now().UTC(),
			}
			if err := cache.CachePutItem(*id, payload, meta); err != nil {
				fail("cache error: %v", err)
			}
			writePayload(payload, *out)
			return
		}
		if err != nil && !isOfflineErr(err) {
			fail("request error: %v", err)
		}
		if err == nil && status != http.StatusOK {
			fail("get failed: %s", readAPIError(respBody))
		}
	}

	payload, meta, err := cache.CacheGetItem(*id)
	if err != nil {
		if errors.Is(err, cache.ErrNotFound) {
			fail("not found in cache")
		}
		fail("cache error: %v", err)
	}
	_ = meta
	writePayload(payload, *out)
}

func runOTP(args []string) {
	fs := newFlagSet("otp")
	id := fs.String("id", "", "")
	server := fs.String("server", "", "")
	insecure := fs.Bool("insecure", false, "")
	parseFlags(fs, args)

	if *id == "" {
		fail("missing id")
	}

	cfg, err := cache.LoadConfig()
	if err != nil {
		fail("config error: %v", err)
	}
	cfg, serverURL, cfgChanged := resolveServerURL(cfg, *server)
	if cfgChanged {
		if err := cache.SaveConfig(cfg); err != nil {
			fail("save config: %v", err)
		}
	}

	if cfg.Token != "" {
		status, respBody, err := doRequest(http.MethodGet, serverURL+"/api/v1/items/"+url.PathEscape(*id), nil, cfg.Token, *insecure)
		if err == nil && status == http.StatusOK {
			var resp struct {
				PayloadBase64 string `json:"payload_base64"`
			}
			if err := json.Unmarshal(respBody, &resp); err != nil || resp.PayloadBase64 == "" {
				fail("invalid response")
			}
			payload, err := base64.StdEncoding.DecodeString(resp.PayloadBase64)
			if err != nil {
				fail("invalid payload")
			}
			code, err := otpCode(payload, time.Now().UTC())
			if err != nil {
				fail("otp error")
			}
			fmt.Println(code)
			return
		}
		if err != nil && !isOfflineErr(err) {
			fail("request error: %v", err)
		}
		if err == nil && status != http.StatusOK {
			fail("otp failed: %s", readAPIError(respBody))
		}
	}

	payload, _, err := cache.CacheGetItem(*id)
	if err != nil {
		if errors.Is(err, cache.ErrNotFound) {
			fail("not found in cache")
		}
		fail("cache error: %v", err)
	}
	code, err := otpCode(payload, time.Now().UTC())
	if err != nil {
		fail("otp error")
	}
	fmt.Println(code)
}

func runDelete(args []string) {
	fs := newFlagSet("delete")
	id := fs.String("id", "", "")
	server := fs.String("server", "", "")
	insecure := fs.Bool("insecure", false, "")
	parseFlags(fs, args)

	if *id == "" {
		fail("missing id")
	}
	cfg, err := cache.LoadConfig()
	if err != nil {
		fail("config error: %v", err)
	}
	cfg, serverURL, cfgChanged := resolveServerURL(cfg, *server)
	if cfgChanged {
		if err := cache.SaveConfig(cfg); err != nil {
			fail("save config: %v", err)
		}
	}
	if cfg.Token == "" {
		fail("not logged in")
	}
	status, respBody, err := doRequest(http.MethodDelete, serverURL+"/api/v1/items/"+url.PathEscape(*id), nil, cfg.Token, *insecure)
	if err != nil {
		if isOfflineErr(err) {
			fail("offline: read-only mode")
		}
		fail("request error: %v", err)
	}
	if status != http.StatusNoContent {
		fail("delete failed: %s", readAPIError(respBody))
	}
	fmt.Println("ok")
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func parseFlags(fs *flag.FlagSet, args []string) {
	if err := fs.Parse(args); err != nil {
		fail("invalid flags")
	}
}

func resolveServerURL(cfg *cache.Config, serverFlag string) (*cache.Config, string, bool) {
	changed := false
	if cfg == nil {
		cfg = &cache.Config{}
	}
	serverURL := cfg.ServerURL
	if serverFlag != "" {
		serverURL = serverFlag
		cfg.ServerURL = serverFlag
		changed = true
	}
	if serverURL == "" {
		serverURL = "https://localhost:8443"
	}
	serverURL = strings.TrimRight(serverURL, "/")
	return cfg, serverURL, changed
}

func doRequest(method, urlStr string, body interface{}, token string, insecure bool) (int, []byte, error) {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, urlStr, bodyReader)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := http.Client{
		Timeout: 10 * time.Second,
	}
	if insecure {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, respBody, nil
}

func readAPIError(body []byte) string {
	var resp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &resp); err == nil && resp.Error != "" {
		return resp.Error
	}
	s := strings.TrimSpace(string(body))
	if s == "" {
		return "unknown error"
	}
	return s
}

func validType(t string) bool {
	switch t {
	case "creds", "card", "text", "binary", "otp":
		return true
	default:
		return false
	}
}

func parseMeta(meta string) ([]byte, error) {
	if strings.TrimSpace(meta) == "" {
		return []byte(`{}`), nil
	}
	m := map[string]string{}
	parts := strings.Split(meta, ",")
	for _, p := range parts {
		if strings.TrimSpace(p) == "" {
			continue
		}
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			return nil, errors.New("invalid meta")
		}
		k := strings.TrimSpace(kv[0])
		v := strings.TrimSpace(kv[1])
		if k == "" {
			return nil, errors.New("invalid meta")
		}
		m[k] = v
	}
	return json.Marshal(m)
}

func isOfflineErr(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return true
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "tls") || strings.Contains(msg, "x509") || strings.Contains(msg, "handshake") {
		return true
	}
	if strings.Contains(msg, "connection refused") || strings.Contains(msg, "no such host") || strings.Contains(msg, "network is unreachable") {
		return true
	}
	return false
}

func listFromCache(search string) {
	items, err := cache.CacheListItems()
	if err != nil {
		fail("cache error: %v", err)
	}
	if strings.TrimSpace(search) != "" {
		items = filterCached(items, search)
	}
	if len(items) == 0 {
		fail("offline: read-only mode")
	}
	printList(items)
}

func printList(items []cache.CachedMeta) {
	for _, it := range items {
		fmt.Printf("%s %s %s\n", it.ID, it.Type, it.UpdatedAt.Format(time.RFC3339))
	}
}

func saveCacheList(items []cache.CachedMeta) error {
	return cache.CacheSaveList(items)
}

func filterCached(items []cache.CachedMeta, q string) []cache.CachedMeta {
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" {
		return items
	}
	out := make([]cache.CachedMeta, 0, len(items))
	for _, it := range items {
		if strings.Contains(strings.ToLower(string(it.Metadata)), q) {
			out = append(out, it)
		}
	}
	return out
}

func writePayload(payload []byte, out string) {
	if out != "" {
		if err := os.WriteFile(out, payload, 0600); err != nil {
			fail("write file: %v", err)
		}
		fmt.Println(out)
		return
	}
	fmt.Println(base64.StdEncoding.EncodeToString(payload))
}

func otpCode(payload []byte, now time.Time) (string, error) {
	secret := decodeOTPSecret(payload)
	if len(secret) == 0 {
		return "", errors.New("empty secret")
	}
	counter := uint64(now.Unix() / 30)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := (int(sum[offset])&0x7f)<<24 |
		(int(sum[offset+1])&0xff)<<16 |
		(int(sum[offset+2])&0xff)<<8 |
		(int(sum[offset+3]) & 0xff)
	code = code % 1000000
	return fmt.Sprintf("%06d", code), nil
}

func decodeOTPSecret(payload []byte) []byte {
	s := strings.TrimSpace(string(payload))
	if s == "" {
		return nil
	}
	s = strings.ToUpper(strings.ReplaceAll(s, " ", ""))
	b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err == nil && len(b) > 0 {
		return b
	}
	return []byte(s)
}

func fail(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if os.Getenv("GOPHKEEPER_TESTING") == "1" {
		panic(msg)
	}
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}
