package crypto

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	masterKey := bytes.Repeat([]byte{1}, 32)
	plaintext := []byte("hello world")

	ciphertext, payloadNonce, encDEK, dekNonce, err := EncryptPayload(masterKey, plaintext)
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}

	got, err := DecryptPayload(masterKey, ciphertext, payloadNonce, encDEK, dekNonce)
	if err != nil {
		t.Fatalf("decrypt error: %v", err)
	}

	if !bytes.Equal(got, plaintext) {
		t.Fatalf("mismatch: got %q want %q", got, plaintext)
	}
}

func TestDecryptWrongMasterKey(t *testing.T) {
	masterKey := bytes.Repeat([]byte{2}, 32)
	plaintext := []byte("data")

	ciphertext, payloadNonce, encDEK, dekNonce, err := EncryptPayload(masterKey, plaintext)
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}

	badKey := bytes.Repeat([]byte{3}, 32)
	_, err = DecryptPayload(badKey, ciphertext, payloadNonce, encDEK, dekNonce)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestDecryptTampered(t *testing.T) {
	masterKey := bytes.Repeat([]byte{4}, 32)
	plaintext := []byte("data")

	ciphertext, payloadNonce, encDEK, dekNonce, err := EncryptPayload(masterKey, plaintext)
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}

	badCipher := append([]byte(nil), ciphertext...)
	badCipher[0] ^= 0xFF
	_, err = DecryptPayload(masterKey, badCipher, payloadNonce, encDEK, dekNonce)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestLoadMasterKeyFromEnv(t *testing.T) {
	key := bytes.Repeat([]byte{9}, 32)
	val := base64.StdEncoding.EncodeToString(key)
	t.Setenv("TEST_MASTER_KEY", val)

	got, err := LoadMasterKeyFromEnv("TEST_MASTER_KEY")
	if err != nil {
		t.Fatalf("load error: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatalf("mismatch")
	}
}

func TestLoadMasterKeyFromEnvMissing(t *testing.T) {
	t.Setenv("MISSING_KEY", "")
	_, err := LoadMasterKeyFromEnv("MISSING_KEY")
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestLoadMasterKeyFromEnvBadLen(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 31)
	val := base64.StdEncoding.EncodeToString(key)
	t.Setenv("BAD_KEY", val)
	_, err := LoadMasterKeyFromEnv("BAD_KEY")
	if err == nil {
		t.Fatalf("expected error")
	}
}
