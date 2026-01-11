// Package crypto provides payload encryption helpers.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
)

// LoadMasterKeyFromEnv loads a base64 master key from env.
func LoadMasterKeyFromEnv(envName string) ([]byte, error) {
	val := os.Getenv(envName)
	if val == "" {
		return nil, fmt.Errorf("missing %s", envName)
	}
	decoded, err := base64.StdEncoding.DecodeString(val)
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", envName, err)
	}
	if len(decoded) != 32 {
		return nil, fmt.Errorf("invalid %s length: %d", envName, len(decoded))
	}
	return decoded, nil
}

// EncryptPayload encrypts plaintext and wraps the per-item key.
func EncryptPayload(masterKey []byte, plaintext []byte) (ciphertext, payloadNonce, encDEK, dekNonce []byte, err error) {
	if len(masterKey) != 32 {
		return nil, nil, nil, nil, fmt.Errorf("invalid master key length: %d", len(masterKey))
	}

	dek := make([]byte, 32)
	if _, err = rand.Read(dek); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("generate dek: %w", err)
	}
	payloadNonce = make([]byte, 12)
	if _, err = rand.Read(payloadNonce); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("generate payload nonce: %w", err)
	}
	dekNonce = make([]byte, 12)
	if _, err = rand.Read(dekNonce); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("generate dek nonce: %w", err)
	}

	payloadGCM, err := newGCM(dek)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("payload gcm: %w", err)
	}
	ciphertext = payloadGCM.Seal(nil, payloadNonce, plaintext, nil)

	masterGCM, err := newGCM(masterKey)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("master gcm: %w", err)
	}
	encDEK = masterGCM.Seal(nil, dekNonce, dek, nil)

	return ciphertext, payloadNonce, encDEK, dekNonce, nil
}

// DecryptPayload decrypts ciphertext using the wrapped key.
func DecryptPayload(masterKey []byte, ciphertext, payloadNonce, encDEK, dekNonce []byte) ([]byte, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("invalid master key length: %d", len(masterKey))
	}
	masterGCM, err := newGCM(masterKey)
	if err != nil {
		return nil, fmt.Errorf("master gcm: %w", err)
	}
	dek, err := masterGCM.Open(nil, dekNonce, encDEK, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt dek: %w", err)
	}
	payloadGCM, err := newGCM(dek)
	if err != nil {
		return nil, fmt.Errorf("payload gcm: %w", err)
	}
	plaintext, err := payloadGCM.Open(nil, payloadNonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt payload: %w", err)
	}
	return plaintext, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm, nil
}
