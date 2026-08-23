package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
)

func GenerateSigningKey() (publicKey, privateKey string, err error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return EncodeKey(public), EncodeKey(private), nil
}

func EncodeKey(key []byte) string {
	return base64.RawURLEncoding.EncodeToString(key)
}

func DecodePublicKey(encoded string) (ed25519.PublicKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("invalid public key length")
	}
	return ed25519.PublicKey(raw), nil
}

func DecodePrivateKey(encoded string) (ed25519.PrivateKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid private key length")
	}
	return ed25519.PrivateKey(raw), nil
}

func SignJSON(privateKey string, value any) (string, error) {
	private, err := DecodePrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return EncodeKey(ed25519.Sign(private, payload)), nil
}

func VerifyJSON(publicKey string, value any, signature string) error {
	public, err := DecodePublicKey(publicKey)
	if err != nil {
		return err
	}
	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return err
	}
	if len(sig) != ed25519.SignatureSize {
		return errors.New("invalid signature length")
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if !ed25519.Verify(public, payload, sig) {
		return errors.New("signature verification failed")
	}
	return nil
}

func SignBytes(privateKey string, payload []byte) (string, error) {
	private, err := DecodePrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	return EncodeKey(ed25519.Sign(private, payload)), nil
}

func VerifyBytes(publicKey string, payload []byte, signature string) error {
	public, err := DecodePublicKey(publicKey)
	if err != nil {
		return err
	}
	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return err
	}
	if len(sig) != ed25519.SignatureSize {
		return errors.New("invalid signature length")
	}
	if !ed25519.Verify(public, payload, sig) {
		return errors.New("signature verification failed")
	}
	return nil
}
