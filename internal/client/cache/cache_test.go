package cache

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConfigLoadSave(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GOPHKEEPER_HOME", dir)

	cfg := &Config{ServerURL: "https://localhost:8443", Token: "t1"}
	err := SaveConfig(cfg)
	if err != nil {
		t.Fatalf("save config: %v", err)
	}
	got, err := LoadConfig()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if got.ServerURL != cfg.ServerURL || got.Token != cfg.Token {
		t.Fatalf("config mismatch")
	}
}

func TestCachePutListGet(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GOPHKEEPER_HOME", dir)

	meta := CachedMeta{
		Type:      "text",
		Metadata:  json.RawMessage(`{"a":1}`),
		UpdatedAt: time.Now().UTC(),
	}
	payload := []byte("hello")
	if err := CachePutItem("id1", payload, meta); err != nil {
		t.Fatalf("cache put: %v", err)
	}

	list, err := CacheListItems()
	if err != nil {
		t.Fatalf("cache list: %v", err)
	}
	if len(list) != 1 || list[0].ID != "id1" {
		t.Fatalf("unexpected list")
	}

	data, gotMeta, err := CacheGetItem("id1")
	if err != nil {
		t.Fatalf("cache get: %v", err)
	}
	if !bytes.Equal(data, payload) {
		t.Fatalf("payload mismatch")
	}
	if gotMeta.Type != "text" {
		t.Fatalf("meta mismatch")
	}
}

func TestCachePutUpdate(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GOPHKEEPER_HOME", dir)

	meta := CachedMeta{Type: "text", UpdatedAt: time.Now().UTC()}
	if err := CachePutItem("id1", []byte("a"), meta); err != nil {
		t.Fatalf("cache put: %v", err)
	}
	meta.Type = "binary"
	if err := CachePutItem("id1", []byte("b"), meta); err != nil {
		t.Fatalf("cache put: %v", err)
	}
	list, err := CacheListItems()
	if err != nil {
		t.Fatalf("cache list: %v", err)
	}
	if len(list) != 1 || list[0].Type != "binary" {
		t.Fatalf("update failed")
	}
}

func TestCacheGetMissing(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GOPHKEEPER_HOME", dir)

	_, _, err := CacheGetItem("missing")
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestCacheSaveList(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GOPHKEEPER_HOME", dir)

	items := []CachedMeta{
		{ID: "id1", Type: "text", UpdatedAt: time.Now().UTC()},
		{ID: "id2", Type: "binary", UpdatedAt: time.Now().UTC()},
	}
	if err := CacheSaveList(items); err != nil {
		t.Fatalf("save list: %v", err)
	}
	got, err := CacheListItems()
	if err != nil {
		t.Fatalf("load list: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("list size")
	}
}

func TestBaseDirEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GOPHKEEPER_HOME", dir)
	got, err := baseDir()
	if err != nil {
		t.Fatalf("base dir: %v", err)
	}
	if got != dir {
		t.Fatalf("expected env dir")
	}
}

func TestLoadConfigBadJSON(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GOPHKEEPER_HOME", dir)
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte("{bad"), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	_, err := LoadConfig()
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestCacheGetMissingFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GOPHKEEPER_HOME", dir)
	items := []CachedMeta{{ID: "id1", Type: "text", UpdatedAt: time.Now().UTC()}}
	if err := CacheSaveList(items); err != nil {
		t.Fatalf("save list: %v", err)
	}
	_, _, err := CacheGetItem("id1")
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestBaseDirDefault(t *testing.T) {
	t.Setenv("GOPHKEEPER_HOME", "")
	got, err := baseDir()
	if err != nil {
		t.Fatalf("base dir: %v", err)
	}
	if !strings.HasSuffix(got, ".gophkeeper") {
		t.Fatalf("unexpected dir")
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GOPHKEEPER_HOME", dir)
	_, err := LoadConfig()
	if err != nil {
		t.Fatalf("unexpected error")
	}
}
