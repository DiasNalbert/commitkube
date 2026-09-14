package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

const prefix = "enc:"

func MasterKey() []byte {
	val := os.Getenv("ENCRYPTION_KEY")
	if val == "" {
		log.Println("Warning: ENCRYPTION_KEY not set — secrets stored in plaintext")
		return nil
	}
	key, err := hex.DecodeString(val)
	if err != nil || len(key) != 32 {
		log.Fatalf("ENCRYPTION_KEY must be exactly 64 hex characters (32 bytes); got %d chars", len(val))
	}
	return key
}

func Encrypt(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("crypto: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("crypto: new gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("crypto: nonce: %w", err)
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return prefix + base64.StdEncoding.EncodeToString(ciphertext), nil
}

func Decrypt(key []byte, value string) (string, error) {
	if !strings.HasPrefix(value, prefix) {
		return value, nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, prefix))
	if err != nil {
		return "", fmt.Errorf("crypto: base64 decode: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("crypto: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("crypto: new gcm: %w", err)
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return "", fmt.Errorf("crypto: ciphertext too short")
	}
	plaintext, err := gcm.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return "", fmt.Errorf("crypto: decrypt: %w", err)
	}
	return string(plaintext), nil
}

func EncryptField(key []byte, s string) string {
	if key == nil || s == "" || strings.HasPrefix(s, prefix) {
		return s
	}
	enc, err := Encrypt(key, s)
	if err != nil {
		log.Printf("crypto: encrypt error: %v", err)
		return s
	}
	return enc
}

func DecryptField(key []byte, s string) string {
	if key == nil || s == "" {
		return s
	}
	dec, err := Decrypt(key, s)
	if err != nil {
		log.Printf("crypto: decrypt error: %v", err)
		return s
	}
	return dec
}

func DecryptFields(key []byte, fields ...*string) {
	for _, f := range fields {
		if f != nil {
			*f = DecryptField(key, *f)
		}
	}
}
