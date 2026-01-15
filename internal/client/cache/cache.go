package cache

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

var ErrNotFound = errors.New("not found")

type Config struct {
	ServerURL string `json:"server_url"`
	Token     string `json:"token"`
}

type CachedMeta struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	Metadata  json.RawMessage `json:"metadata"`
	UpdatedAt time.Time       `json:"updated_at"`
	LocalPath string          `json:"local_path,omitempty"`
}

func LoadConfig() (*Config, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func SaveConfig(cfg *Config) error {
	if cfg == nil {
		cfg = &Config{}
	}
	if err := EnsureDirs(); err != nil {
		return err
	}
	path, err := configPath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func EnsureDirs() error {
	base, err := baseDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(base, 0700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(base, "cache"), 0700); err != nil {
		return err
	}
	return os.MkdirAll(filepath.Join(base, "cache", "items"), 0700)
}

func CachePutItem(id string, payloadBytes []byte, meta CachedMeta) error {
	if err := EnsureDirs(); err != nil {
		return err
	}
	if meta.UpdatedAt.IsZero() {
		meta.UpdatedAt = time.Now().UTC()
	}
	meta.ID = id
	itemPath, err := itemPath(id)
	if err != nil {
		return err
	}
	if err := os.WriteFile(itemPath, payloadBytes, 0600); err != nil {
		return err
	}
	meta.LocalPath = itemPath

	list, err := CacheListItems()
	if err != nil {
		return err
	}
	updated := false
	for i := range list {
		if list[i].ID == id {
			list[i] = meta
			updated = true
			break
		}
	}
	if !updated {
		list = append(list, meta)
	}
	return saveIndex(list)
}

func CacheListItems() ([]CachedMeta, error) {
	path, err := indexPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []CachedMeta{}, nil
		}
		return nil, err
	}
	var list []CachedMeta
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	return list, nil
}

func CacheSaveList(list []CachedMeta) error {
	if err := EnsureDirs(); err != nil {
		return err
	}
	return saveIndex(list)
}

func CacheGetItem(id string) ([]byte, CachedMeta, error) {
	list, err := CacheListItems()
	if err != nil {
		return nil, CachedMeta{}, err
	}
	var meta CachedMeta
	found := false
	for _, m := range list {
		if m.ID == id {
			meta = m
			found = true
			break
		}
	}
	if !found {
		return nil, CachedMeta{}, ErrNotFound
	}
	path := meta.LocalPath
	if path == "" {
		path, err = itemPath(id)
		if err != nil {
			return nil, CachedMeta{}, err
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, CachedMeta{}, ErrNotFound
		}
		return nil, CachedMeta{}, err
	}
	return data, meta, nil
}

func baseDir() (string, error) {
	if v := os.Getenv("GOPHKEEPER_HOME"); v != "" {
		return v, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".gophkeeper"), nil
}

func configPath() (string, error) {
	base, err := baseDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "config.json"), nil
}

func indexPath() (string, error) {
	base, err := baseDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "cache", "index.json"), nil
}

func itemPath(id string) (string, error) {
	base, err := baseDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "cache", "items", id+".bin"), nil
}

func saveIndex(list []CachedMeta) error {
	path, err := indexPath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}
