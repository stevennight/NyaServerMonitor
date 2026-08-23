package controller

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"strings"
)

type secretBox struct {
	aead cipher.AEAD
}

func newSecretBox(raw string) *secretBox {
	raw = strings.TrimSpace(raw)
	if len(raw) < 16 {
		return nil
	}
	key := sha256.Sum256([]byte(raw))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}
	return &secretBox{aead: aead}
}

func (b *secretBox) seal(value string) (string, error) {
	if b == nil || b.aead == nil {
		return "", errors.New("encryption key is not configured")
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b.aead.Seal(nonce, nonce, []byte(value), nil)), nil
}

func (b *secretBox) open(value string) (string, error) {
	if b == nil || b.aead == nil {
		return "", errors.New("encryption key is not configured")
	}
	encoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(encoded) < b.aead.NonceSize() {
		return "", errors.New("invalid encrypted value")
	}
	nonce := encoded[:b.aead.NonceSize()]
	plaintext, err := b.aead.Open(nil, nonce, encoded[b.aead.NonceSize():], nil)
	if err != nil {
		return "", errors.New("unable to decrypt value")
	}
	return string(plaintext), nil
}
