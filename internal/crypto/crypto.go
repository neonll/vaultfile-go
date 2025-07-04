package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

const (
	// RSAKeySize is the minimum secure RSA key size in bits
	RSAKeySize = 2048
	// AESKeySize is the AES key size in bytes (256 bits)
	AESKeySize = 32
	// AESBlockSize is the AES block size in bytes
	AESBlockSize = 16
)

// EncryptionResult holds the result of AES encryption
type EncryptionResult struct {
	AESKey        []byte
	EncryptedData string
}

// GenerateRSAKey generates a new RSA private key with the specified bit size
func GenerateRSAKey(bits int) (*rsa.PrivateKey, error) {
	if bits < RSAKeySize {
		return nil, fmt.Errorf("RSA key size must be at least %d bits", RSAKeySize)
	}
	return rsa.GenerateKey(rand.Reader, bits)
}

// EncryptRSAOAEP encrypts data using RSA with OAEP padding
func EncryptRSAOAEP(pubKey *rsa.PublicKey, data []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, data, nil)
}

// DecryptRSAOAEP decrypts data using RSA with OAEP padding
func DecryptRSAOAEP(privKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), nil, privKey, ciphertext, nil)
}

// EncryptAESGCM encrypts data using AES-GCM
func EncryptAESGCM(key []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptAESGCM decrypts data using AES-GCM
func DecryptAESGCM(key []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// EncryptSecretUTF8 encrypts a UTF-8 string secret
func EncryptSecretUTF8(secret string) (*EncryptionResult, error) {
	return encryptByteSequence([]byte(secret))
}

// EncryptSecretBase64 encrypts a base64-encoded secret
func EncryptSecretBase64(secretBase64 string) (*EncryptionResult, error) {
	rawSecret, err := base64.StdEncoding.DecodeString(secretBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 secret: %w", err)
	}
	return encryptByteSequence(rawSecret)
}

// encryptByteSequence encrypts a byte sequence using AES-GCM
func encryptByteSequence(plaintext []byte) (*EncryptionResult, error) {
	// Generate a random AES key
	key := make([]byte, AESKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate AES key: %w", err)
	}

	// Encrypt the plaintext
	ciphertext, err := EncryptAESGCM(key, plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %w", err)
	}

	// Encode the ciphertext as base64
	encryptedData := base64.StdEncoding.EncodeToString(ciphertext)

	return &EncryptionResult{
		AESKey:        key,
		EncryptedData: encryptedData,
	}, nil
}

// DecryptSecret decrypts a secret using the provided AES key
func DecryptSecret(encryptedDataBase64 string, key []byte) (string, error) {
	// Decode the base64-encoded ciphertext
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedDataBase64)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 ciphertext: %w", err)
	}

	// Decrypt the ciphertext
	plaintext, err := DecryptAESGCM(key, ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt data: %w", err)
	}

	return string(plaintext), nil
}

// GenerateAESKey generates a new AES key
func GenerateAESKey() ([]byte, error) {
	key := make([]byte, AESKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate AES key: %w", err)
	}
	return key, nil
}
